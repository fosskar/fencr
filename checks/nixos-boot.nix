self: pkgs:

# Boots the nixos surface end to end: a fencr vm on a nixos host beside a
# second machine on a test lan, then real traffic through the forward, ssh
# over vsock, the secret, the seal, the broker and the state tree.
let
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  documentRoot = pkgs.writeTextDir "index.html" "fencr ingress\n";
  targetRoot = pkgs.writeTextDir "index.html" "fencr target\n";
  rawSecret = pkgs.writeText "fencr-test-secret" "fencr secret\n";
  brokerSecret = pkgs.writeText "fencr-test-broker-secret" "Bearer fencr-broker-token\n";
  # the brokered api: echoes the Authorization header it received
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
          x86_64-linux = "kvm64,+svm,+vmx";
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
        # the seal: closed egress with one pinhole into the test network
        allowedTCPDestinations = [ "192.168.1.2:8123" ];
        expose = [
          {
            listenAddress = "127.0.0.1";
            listenPort = 22100;
            guestPort = 9119;
          }
        ];
        # the credential broker: the guest calls 127.0.0.1:8765, the host
        # injects the bearer token, the value never enters the vm
        hostForwards = [
          {
            vsockPort = 18765;
            targetPort = 8765;
            broker.secretFile = brokerSecret;
          }
        ];
        services = [
          {
            environment.systemPackages = [ pkgs.curl ];
            systemd.services.ingress = {
              wantedBy = [ "multi-user.target" ];
              serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9119 --bind 127.0.0.1 --directory ${documentRoot}";
            };
          }
        ];
      };

      system.stateVersion = "25.11";
    };

    # a machine beside the host on the test network: the pinhole target on
    # 8123, and a listener on 80 that the seal must keep unreachable
    nodes.target = {
      networking.firewall.allowedTCPPorts = [
        80
        8123
      ];
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
      ssh = "ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o 'ProxyCommand=${pkgs.socat}/bin/socat - VSOCK-CONNECT:3:22' root@sbx"

      target.wait_for_unit("target-8123.service")
      target.wait_for_unit("target-80.service")
      host.wait_for_unit("microvm@sbx.service", timeout=1200)
      host.wait_for_unit("sbx-forward-22100.socket")
      host.wait_until_succeeds("curl --fail --silent http://127.0.0.1:22100 | grep -Fx 'fencr ingress'", timeout=120)
      host.fail("nc -z -w 2 10.30.1.2 22")

      host.succeed("install -d -m 0700 /root/.ssh")
      host.succeed("install -m 0600 '${snakeOilEd25519PrivateKey}' /root/.ssh/id_ed25519")
      host.wait_until_succeeds(f"{ssh} 'printf fencr-ssh' | grep -Fx fencr-ssh", timeout=300)
      host.succeed(f"{ssh} 'cat /run/agent-secrets/raw' | grep -Fx 'fencr secret'", timeout=60)

      host.succeed(f"{ssh} 'findmnt -n -o FSTYPE /nix/store' | grep -Fx erofs", timeout=60)
      # the test host exposes svm and vmx; the guest must not see either
      host.fail(f"{ssh} 'grep -qwE \"svm|vmx\" /proc/cpuinfo'", timeout=60)
      host.fail(f"{ssh} 'touch /nix/store/fencr-probe'", timeout=60)
      host.succeed("findmnt -n -o OPTIONS /var/lib/fencr-vms/sbx | grep nosuid | grep nodev | grep -q noexec")
      host.succeed(f"{ssh} 'cp /run/current-system/sw/bin/true /var/lib/fencr-probe && chmod 4755 /var/lib/fencr-probe'", timeout=60)
      host.succeed("test -u /var/lib/fencr-vms/sbx/fencr-probe")
      host.fail("/var/lib/fencr-vms/sbx/fencr-probe")

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

      # the credential broker, end to end: the guest sees the header injected,
      # the upstream called directly sees none, and the broker has no tcp port
      host.wait_for_unit("upstream-8765.service")
      host.wait_for_unit("sbx-broker-18765.service")
      host.succeed("test -S /run/fencr-broker-sbx-18765/broker.sock")
      host.succeed("curl --fail --silent http://127.0.0.1:8765/ | grep -Fx 'authorization: None'", timeout=60)
      host.succeed(f"{ssh} 'curl --fail --silent --max-time 5 http://127.0.0.1:8765/' | grep -Fx 'authorization: Bearer fencr-broker-token'", timeout=60)
      host.fail(f"{ssh} 'grep -r fencr-broker-token /run/agent-secrets /proc/self/environ'", timeout=60)
    '';

    meta.timeout = 1800;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
