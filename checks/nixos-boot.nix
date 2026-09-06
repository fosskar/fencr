self: pkgs:

# Boots the nixos surface end to end and drives real traffic through every
# path the module promises.
let
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  documentRoot = pkgs.writeTextDir "index.html" "fencr ingress\n";
  targetRoot = pkgs.writeTextDir "index.html" "fencr target\n";
  credentialFile = pkgs.writeText "fencr-test-credential" "Bearer fencr-api-token\n";
  rawSecret = pkgs.writeText "fencr-test-secret" "fencr secret\n";
  # the api behind the credential: echoes the Authorization header it received
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
  # the site behind an allowed name: tls with a throwaway certificate
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

      networking.useNetworkd = true;
      networking.nameservers = [ "9.9.9.9" ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.netcat
        pkgs.openssh
      ];

      # a globally opened host port: the seal must still keep it from the vm
      networking.firewall.allowedTCPPorts = [ 80 ];
      networking.firewall.filterForward = true;
      systemd.services.host-80 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind 0.0.0.0 --directory ${targetRoot}";
      };
      # a host that already serves *:443 and *:53, as one with its own web
      # server and resolver does; the egress proxy must live beside them
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
        # the seal: closed egress with one pinhole into the test network,
        # and one name allowed over tls; both names resolve to the target
        # on the host, only one is on the list
        allowedTCPDestinations = [ "192.168.1.2:8123" ];
        allowedDomains = [ "allowed.test" ];
        # the web ui: reachable from the host at the guest's address, on
        # this port and no other
        expose = [ 9119 ];
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
      };

      networking.hosts."192.168.1.2" = [
        "allowed.test"
        "denied.test"
      ];
      # the test network is a private range the proxy unit denies; allow
      # the one target, which is the "internet" here
      systemd.services.fencr-sbx-egress-proxy.serviceConfig.IPAddressAllow = [ "192.168.1.2/32" ];

      system.stateVersion = "25.11";
    };

    # a machine beside the host on the test network: the pinhole target on
    # 8123, and a listener on 80 that the seal must keep unreachable
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
      ssh = "ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.30.1.2"

      target.wait_for_unit("target-8123.service")
      target.wait_for_unit("target-80.service")
      host.wait_for_unit("fencr-sbx.service", timeout=1200)
      # the guest at its address: the exposed port answers, the other one
      # and everything else the host tries is dropped by the seal's output
      # chain before it leaves the host
      host.wait_until_succeeds("curl --fail --silent http://10.30.1.2:9119 | grep -Fx 'fencr ingress'", timeout=120)
      host.fail("curl --silent --max-time 3 http://10.30.1.2:9120")
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:guest-blocked\"' | grep -qv 'packets 0 '")
      host.succeed("nc -z -w 2 10.30.1.2 22")

      host.succeed("install -d -m 0700 /root/.ssh")
      host.succeed("install -m 0600 '${snakeOilEd25519PrivateKey}' /root/.ssh/id_ed25519")
      host.wait_until_succeeds(f"{ssh} 'printf fencr-ssh' | grep -Fx fencr-ssh", timeout=300)
      # a raw secret arrived over vsock, readable by guest root only
      host.succeed(f"{ssh} 'cat /run/agent-secrets/raw' | grep -Fx 'fencr secret'", timeout=60)
      host.succeed(f"{ssh} 'stat -c %a /run/agent-secrets/raw' | grep -Fx 400", timeout=60)
      host.succeed("test \"$(stat -c %U:%a /run/fencr-sbx/vsock_5)\" = fencr-sbx:600")
      # the vm's vsock sockets belong to its user
      host.succeed("test \"$(stat -c %U:%a /run/fencr-sbx/vsock)\" = fencr-sbx:770")

      host.succeed(f"{ssh} 'findmnt -n -o FSTYPE /nix/store' | grep -Fx erofs", timeout=60)
      # the test host exposes svm and vmx; the guest must not see either
      host.fail(f"{ssh} 'grep -qwE \"svm|vmx\" /proc/cpuinfo'", timeout=60)
      host.fail(f"{ssh} 'touch /nix/store/fencr-probe'", timeout=60)
      # the state tree is one image owned by the vm's user, and it outlives
      # the vm: what the guest writes is there again after a restart
      host.succeed("test \"$(stat -c %U:%a /var/lib/fencr-vms/sbx/state.img)\" = fencr-sbx:660")
      host.succeed(f"{ssh} 'findmnt -n -o SOURCE /var/lib' | grep -Fx /dev/vdb", timeout=60)
      host.succeed(f"{ssh} 'echo survives > /var/lib/fencr-probe'", timeout=60)
      host.succeed("systemctl restart fencr-sbx.service")
      # a clean stop, not a kill after the stop timeout
      host.fail("journalctl -u fencr-sbx.service | grep -q 'Stopping timed out'")
      host.wait_until_succeeds(f"{ssh} 'cat /var/lib/fencr-probe' | grep -Fx survives", timeout=300)

      # the seal, probed with real packets from inside the vm. every probe
      # carries a timeout: a hang here means the seal swallowed the reply
      # and the test should say so rather than wait
      host.succeed("nft list table inet fencr-sbx | grep -q 'fencr:sbx:blocked'")
      host.succeed(f"{ssh} 'curl --fail --silent --max-time 5 http://192.168.1.2:8123' | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://192.168.1.2:80'", timeout=60)
      host.wait_for_unit("host-80.service")
      host.succeed("curl --fail --silent http://127.0.0.1:80 | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://10.30.1.1:80'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://192.168.1.1:80'", timeout=60)
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:blocked\"' | grep -qv 'packets 0 '")
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:host-blocked\"' | grep -qv 'packets 0 '")

      # egress by name: every name resolves to the host, the allowed one is
      # passed through to the real site, the other is refused by name, and a
      # raw address on 443 hits the closed forward chain
      target.wait_for_unit("target-443.service")
      host.wait_for_unit("fencr-sbx-egress-proxy.service")
      host.succeed(f"{ssh} 'getent hosts denied.test' | grep -q '^10.30.1.1 '", timeout=60)
      host.succeed(f"{ssh} 'curl --fail --silent --insecure --max-time 10 https://allowed.test/' | grep -Fx 'fencr target'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --insecure --max-time 10 https://denied.test/'", timeout=60)
      host.fail(f"{ssh} 'curl --silent --insecure --max-time 5 https://192.168.1.2/'", timeout=60)
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'allow allowed.test'")
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'deny denied.test'")

      # the credential, end to end: the guest calls the domain over https
      # and trusts the host's authority without being told to, whatever it
      # sent as a header is replaced, the upstream called directly sees
      # none, and the proxy has no tcp port
      host.wait_for_unit("upstream-8765.service")
      host.wait_for_unit("fencr-sbx-credentials.service")
      host.succeed("test \"$(stat -c %U:%a /var/lib/fencr/ca/root.key)\" = root:600")
      host.succeed("test -S /run/fencr-credentials-sbx/credentials.sock")
      host.succeed("curl --fail --silent http://127.0.0.1:8765/ | grep -Fx 'authorization: None'", timeout=60)
      host.succeed(f"{ssh} 'test -e /run/fencr/ca-bundle.crt && test ! -e /run/agent-secrets/fencr-ca.crt'", timeout=60)
      host.succeed(f"{ssh} 'curl --fail --silent --max-time 10 -H \"Authorization: Bearer placeholder\" https://api.test/' | grep -Fx 'authorization: Bearer fencr-api-token'", timeout=60)
      host.succeed("journalctl -u fencr-sbx-egress-proxy.service -o cat | grep -Fx 'intercept api.test'")
      host.fail(f"{ssh} 'grep -r fencr-api-token /proc/self/environ /run'", timeout=60)
    '';

    meta.timeout = 1800;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
