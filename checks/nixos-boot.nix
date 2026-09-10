self: pkgs:

# Boots the nixos surface end to end and drives real traffic through every
# path the module promises. Every probe carries a timeout: a hang means the
# firewall swallowed a reply, and the test should say so rather than wait.
let
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  documentRoot = pkgs.writeTextDir "index.html" "fencr ingress\n";
  targetRoot = pkgs.writeTextDir "index.html" "fencr target\n";
  credentialFile = pkgs.writeText "fencr-test-credential" "Bearer fencr-api-token\n";
  rawSecret = pkgs.writeText "fencr-test-secret" "fencr secret\n";
  # echoes the Authorization header it received
  upstream = pkgs.writeText "fencr-test-upstream.py" ''
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = ("authorization: %s\n" % self.headers.get("Authorization")).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
  '';
  squatter = pkgs.writeText "fencr-test-squatter.py" ''
    import socket, time

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("0.0.0.0", 443))
    tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 53))
    while True:
        time.sleep(3600)
  '';
  tlsCert = pkgs.runCommand "fencr-test-cert" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=allowed.test \
      -keyout $out/key.pem -out $out/cert.pem
  '';
  tlsServer = pkgs.writeText "fencr-test-tls.py" ''
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    import os, ssl

    os.chdir("${targetRoot}")
    server = HTTPServer(("0.0.0.0", 443), SimpleHTTPRequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("${tlsCert}/cert.pem", "${tlsCert}/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
  '';
in
import (pkgs.path + "/nixos/tests/make-test-python.nix")
  ({ pkgs, ... }: {
    name = "fencr-nixos-boot";

    nodes.host = {
      imports = [ self.nixosModules.fencr ];

      virtualisation.qemu.options = [
        "-cpu"
        {
          aarch64-linux = "cortex-a72";
          # firecracker needs xsave state (KVM_CAP_XCRS), which the synthetic
          # kvm64 model does not offer a nested hypervisor
          x86_64-linux = "host";
        }
        .${pkgs.stdenv.hostPlatform.system}
      ];
      virtualisation.diskSize = 4096;
      virtualisation.memorySize = 2048;
      # reflinks, as checkpoints need
      virtualisation.emptyDiskImages = [ 2048 ];
      virtualisation.fileSystems."/var/lib/fencr-vms" = {
        device = "/dev/vdb";
        fsType = "btrfs";
        autoFormat = true;
      };

      networking.useNetworkd = true;
      networking.nameservers = [ "9.9.9.9" ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.netcat
        pkgs.openssh
      ];

      # globally open: the vm's firewall must still keep it from the vm
      networking.firewall.allowedTCPPorts = [ 80 ];
      networking.firewall.filterForward = true;
      systemd.services.host-80 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind 0.0.0.0 --directory ${targetRoot}";
      };
      # a host already serving *:443 and *:53; the egress proxy must live beside it
      systemd.services.host-squatter = {
        wantedBy = [ "multi-user.target" ];
        before = [ "fencr-sbx-egress-proxy.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${squatter}";
      };
      systemd.services.upstream-8765 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${upstream}";
      };

      fencr.vms.sbx = {
        id = 0;
        vcpu = 1;
        mem = 768;
        authorizedKeys = [ snakeOilEd25519PublicKey ];
        secrets.raw = rawSecret;
        # the firewall: closed egress with one pinhole into the test network,
        # and one name allowed over tls; both names resolve to the target
        # on the host, only one is on the list
        # private.test resolves to a private address the proxy unit denies.
        # the wildcard admits every name under allowed.test except the
        # one the deny entry names
        outbound = [
          "192.168.1.2:8123"
          "allowed.test"
          "*.allowed.test"
          "!sub.allowed.test"
          "private.test"
        ];
        # the web ui: reachable from the host at the guest's address, on
        # this port and no other
        inbound = [ 9119 ];
        # generous caps: firecracker must accept the limiter config and
        # nothing below may slow down; the cap itself is not measured
        diskBandwidth = 500;
        networkBandwidth = 100;
        # the credential: the guest calls api.test over https as it would
        # any site, the host ends the tls and injects the bearer token,
        # the value never enters the vm
        credentials = [ "api" ];
        services = [
          (
            { agentSandbox, ... }:
            {
              environment.systemPackages = [ pkgs.curl ];
              # a service on the guest's address waits for the address
              systemd.services.ingress = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9119 --bind ${agentSandbox.ip} --directory ${documentRoot}";
              };
              systemd.services.unexposed = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9120 --bind ${agentSandbox.ip} --directory ${documentRoot}";
              };
            }
          )
        ];
      };

      fencr.credentials.api = {
        upstream = "http://127.0.0.1:8765";
        domain = "api.test";
        secretFile = credentialFile;
        # the credential rides on GET / and nothing else
        allow = [ "GET /" ];
      };

      # a second vm with open egress: the host's resolved answers it on the
      # bridge
      fencr.vms.open = {
        id = 1;
        vcpu = 1;
        mem = 512;
        outbound = [ "internet" ];
        authorizedKeys = [ snakeOilEd25519PublicKey ];
      };

      networking.hosts."192.168.1.2" = [
        "allowed.test"
        "other.allowed.test"
        "denied.test"
      ];
      networking.hosts."192.168.1.1" = [ "private.test" ];
      # the test network is a private range the proxy unit denies; allow
      # the one target, which is the "internet" here
      systemd.services.fencr-sbx-egress-proxy.serviceConfig.IPAddressAllow = [ "192.168.1.2/32" ];

      system.stateVersion = "25.11";
    };

    # a machine beside the host on the test network: the pinhole target on
    # 8123, and a listener on 80 that the firewall must keep unreachable
    nodes.target = {
      networking.firewall.allowedTCPPorts = [
        80
        443
        8123
      ];
      systemd.services.target-443 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${tlsServer}";
      };
      systemd.services.target-8123 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8123 --bind 0.0.0.0 --directory ${targetRoot}";
      };
      systemd.services.target-80 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind 0.0.0.0 --directory ${targetRoot}";
      };
      system.stateVersion = "25.11";
    };

    testScript = ''
      ssh = "ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.11.0.2"

      target.wait_for_unit("target-8123.service")
      target.wait_for_unit("target-80.service")
      host.wait_for_unit("fencr-sbx.service", timeout=1200)
      # the guest at its address: the exposed port answers, the other one
      # and everything else the host tries is dropped by the firewall's output
      # chain before it leaves the host
      host.wait_until_succeeds("curl --fail --silent http://10.11.0.2:9119 | grep -Fx 'fencr ingress'", timeout=120)
      host.fail("curl --silent --max-time 3 http://10.11.0.2:9120")
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:guest-blocked\"' | grep -qv 'packets 0 '")
      host.succeed("nc -z -w 2 10.11.0.2 22")

      host.succeed("install -d -m 0700 /root/.ssh")
      host.succeed("install -m 0600 '${snakeOilEd25519PrivateKey}' /root/.ssh/id_ed25519")
      host.wait_until_succeeds(f"{ssh} 'printf fencr-ssh' | grep -Fx fencr-ssh", timeout=300)
      # a raw secret arrived over vsock, readable by guest root only
      host.succeed(f"{ssh} 'cat /run/agent-secrets/raw' | grep -Fx 'fencr secret'", timeout=60)
      host.succeed(f"{ssh} 'stat -c %a /run/agent-secrets/raw' | grep -Fx 400", timeout=60)
      host.succeed("test \"$(stat -c %U:%a /run/fencr-sbx/vsock_5)\" = fencr-sbx:600")
      # the vm's vsock sockets belong to its user
      host.succeed("test \"$(stat -c %U:%a /run/fencr-sbx/vsock)\" = fencr-sbx:700")

      host.succeed(f"{ssh} 'findmnt -n -o FSTYPE /nix/store' | grep -Fx erofs", timeout=60)
      # the test host exposes svm and vmx; the guest must not see either
      host.fail(f"{ssh} 'grep -qwE \"svm|vmx\" /proc/cpuinfo'", timeout=60)
      host.fail(f"{ssh} 'touch /nix/store/fencr-probe'", timeout=60)
      # the root filesystem is one image owned by the vm's user, and it
      # outlives the vm: what the guest writes, root's home included, is
      # there again after a restart
      host.succeed("test \"$(stat -c %U:%a /var/lib/fencr-vms/sbx/state.img)\" = fencr-sbx:600")
      host.succeed(f"{ssh} 'findmnt -n -o SOURCE /' | grep -Fx /dev/vdb", timeout=60)
      # the state image honours flushes: firecracker's Writeback cache
      # advertises the virtio flush feature, which the guest reports as
      # write-back cache mode; the entropy device shows up as hwrng
      host.succeed(f"{ssh} 'cat /sys/block/vdb/queue/write_cache' | grep -Fx 'write back'", timeout=60)
      host.succeed(f"{ssh} 'test -c /dev/hwrng'", timeout=60)
      # the hypervisor process sits in an empty root: no /etc, no host
      # /var, only the store and the vm's own directories; other users'
      # processes are hidden from its /proc
      pid = host.succeed("systemctl show -p MainPID --value fencr-sbx.service").strip()
      # the store is bound in, so a resolved binary path still works inside
      inside = f"nsenter -t {pid} -m -S $(id -u fencr-sbx) -G $(id -g fencr-sbx) $(dirname $(readlink -f $(command -v ls)))"
      host.succeed(f"{inside}/ls / | tr '\\n' ' ' | grep -qxE '(dev|nix|proc|run|sys|tmp|var| )+'")
      host.fail(f"{inside}/test -e /etc")
      host.fail(f"{inside}/test -e /var/lib/fencr")
      host.succeed(f"{inside}/test -f /var/lib/fencr-vms/sbx/state.img")
      host.fail(f"{inside}/test -d /proc/1")
      host.fail(f"{inside}/test -e /proc/cpuinfo")
      host.succeed(f"{ssh} 'echo survives > ~/fencr-probe'", timeout=60)
      host.succeed("systemctl restart fencr-sbx.service")
      # a clean stop, not a kill after the stop timeout
      host.fail("journalctl -u fencr-sbx.service | grep -q 'Stopping timed out'")
      host.wait_until_succeeds(f"{ssh} 'cat ~/fencr-probe' | grep -Fx survives", timeout=300)

      # the clean stop above left one; a file written after the manual one
      # must vanish on restore while the earlier probe stays
      host.succeed("fencr checkpoints sbx | grep '^stop-'")
      host.succeed("fencr checkpoint sbx before-agent | grep '^before-agent '")
      host.succeed("test \"$(stat -c %U:%a /var/lib/fencr-vms/sbx/checkpoints/before-agent.img)\" = fencr-sbx:600")
      host.succeed(f"{ssh} 'test -f ~/fencr-probe && echo after > ~/fencr-after && sync'", timeout=60)
      host.succeed("fencr restore sbx before-agent")
      host.wait_until_succeeds(f"{ssh} 'cat ~/fencr-probe' | grep -Fx survives", timeout=300)
      host.fail(f"{ssh} 'test -e ~/fencr-after'", timeout=60)
      host.succeed("test \"$(fencr checkpoints sbx | grep -c '^stop-')\" = 2")
      host.succeed("test \"$(stat -c %U:%a /var/lib/fencr-vms/sbx/state.img)\" = fencr-sbx:600")
      host.succeed("fencr checkpoints sbx --rm before-agent | grep -Fx 'removed before-agent'")
      host.fail("fencr checkpoints sbx | grep -q before-agent")
      # a reserved name is the unit's error, relayed by the command
      host.fail("fencr checkpoint sbx stop-now")

      # the firewall, probed with real packets from inside the vm
      host.succeed("nft list table inet fencr-sbx | grep -q 'fencr:sbx:blocked'")
      host.succeed("nft list table inet fencr-sbx | grep -q 'ct count over 2048'")
      host.succeed(f"{ssh} 'curl --fail --silent --max-time 5 http://192.168.1.2:8123' | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://192.168.1.2:80'", timeout=60)
      host.wait_for_unit("host-80.service")
      host.succeed("curl --fail --silent http://127.0.0.1:80 | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://10.11.0.1:80'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://192.168.1.1:80'", timeout=60)
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:blocked\"' | grep -qv 'packets 0 '")
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:host-blocked\"' | grep -qv 'packets 0 '")

      # every name resolves to the host; the allowed one is passed through,
      # the other refused by name, a raw address on 443 by the forward chain
      target.wait_for_unit("target-443.service")
      host.wait_for_unit("fencr-sbx-egress-proxy.service")
      host.succeed(f"{ssh} 'getent hosts denied.test' | grep -q '^10.11.0.1 '", timeout=60)
      host.succeed(f"{ssh} 'curl --fail --silent --insecure --max-time 10 https://allowed.test/' | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --insecure --max-time 10 https://denied.test/'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --insecure --max-time 5 https://192.168.1.2/'", timeout=60)
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'allow allowed.test'")
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'deny denied.test'")
      # the deny entry inside the wildcard grant
      host.succeed(f"{ssh} 'curl --fail --silent --insecure --max-time 10 https://other.allowed.test/' | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --insecure --max-time 10 https://sub.allowed.test/'", timeout=60)
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'allow other.allowed.test'")
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'deny sub.allowed.test'")
      # an allowed name resolving into the lan: the unit's deny list drops the
      # syn, so the connect times out where the squatter would have answered
      host.fail(f"{ssh} 'curl --silent --insecure --max-time 15 https://private.test/'", timeout=60)
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'allow private.test'")
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'relay: connection timed out'")

      # the guest trusts the host's authority without being told to, and
      # whatever it sent as a header is replaced
      host.wait_for_unit("upstream-8765.service")
      host.wait_for_unit("fencr-sbx-credentials.service")
      host.succeed("test \"$(stat -c %U:%a /var/lib/fencr/ca/root.key)\" = root:600")
      host.succeed("test -S /run/fencr-sbx-credentials/credentials.sock")
      host.succeed("curl --fail --silent http://127.0.0.1:8765/ | grep -Fx 'authorization: None'", timeout=60)
      host.succeed(f"{ssh} 'test -e /run/fencr/ca-bundle.crt && test ! -e /run/agent-secrets/fencr-ca.crt'", timeout=60)
      host.succeed(f"{ssh} 'curl --fail --silent --max-time 10 -H \"Authorization: Bearer placeholder\" https://api.test/' | grep -Fx 'authorization: Bearer fencr-api-token'", timeout=60)
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'intercept api.test'")
      host.fail(f"{ssh} 'grep -r fencr-api-token /proc/self/environ /run'", timeout=60)
      # the access log holds the request without the headers it carried
      host.succeed("journalctl -u fencr-sbx-credentials.service -o cat | grep -F 'handled request' | grep -F '\"method\":\"GET\"' | grep -F '\"host\":\"api.test\"' | grep -F '\"uri\":\"/\"' | grep -qF '\"status\":200'")
      host.fail("journalctl -u fencr-sbx-credentials.service -o cat | grep -qiF 'placeholder'")
      host.succeed("fencr status sbx | grep -F 'GET api.test/ \u2192 200'")
      # the upstream echoes the header, so its absence shows nothing reached it
      host.succeed(f"{ssh} 'curl --silent --max-time 10 -o /dev/null -w %{{http_code}} -X POST https://api.test/' | grep -Fx 403", timeout=60)
      host.succeed(f"{ssh} 'curl --silent --max-time 10 -X POST https://api.test/other' | grep -Fx \"fencr: request not allowed for credential api\"", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 10 https://api.test/other' | grep -F authorization", timeout=60)
      host.succeed("fencr status sbx | grep -F 'POST api.test/ \u2192 403'")

      # an internet grant resolves through the host's resolved on the bridge
      ssh_open = ssh.replace("10.11.0.2", "10.11.1.2")
      host.wait_for_unit("fencr-open.service", timeout=600)
      host.wait_until_succeeds(f"{ssh_open} 'getent hosts allowed.test' | grep -q '^192.168.1.2 '", timeout=300)
    '';

    meta.timeout = 1800;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
