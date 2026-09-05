self: pkgs:
let
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  documentRoot = pkgs.writeTextDir "index.html" "fencr ingress\n";
  targetRoot = pkgs.writeTextDir "index.html" "fencr target\n";
  rawSecret = pkgs.writeText "fencr-test-secret" "fencr secret\n";
in
import (pkgs.path + "/nixos/tests/make-test-python.nix")
  ({ pkgs, ... }: {
    name = "fencr-ingress";

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

      networking.nameservers = [ "9.9.9.9" ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.netcat
        pkgs.openssh
      ];

      # a globally opened host port: the seal must still keep it from the vm
      networking.firewall.allowedTCPPorts = [ 80 ];
      systemd.services.host-80 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind 0.0.0.0 --directory ${targetRoot}";
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
      host.wait_until_succeeds(f"{ssh} 'printf fencr-ssh' | grep -Fx fencr-ssh", timeout=120)
      host.succeed(f"{ssh} 'cat /run/agent-secrets/raw' | grep -Fx 'fencr secret'")

      # the seal, probed with real packets from inside the vm
      host.succeed("nft list table inet fencr-sbx | grep -q 'fencr:sbx:blocked'")
      host.succeed(f"{ssh} 'curl --fail --silent --max-time 5 http://192.168.1.2:8123' | grep -Fx 'fencr target'")
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://192.168.1.2:80'")
      host.wait_for_unit("host-80.service")
      host.succeed("curl --fail --silent http://127.0.0.1:80 | grep -Fx 'fencr target'")
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://10.30.1.1:80'")
      host.fail(f"{ssh} 'curl --silent --max-time 5 http://192.168.1.1:80'")
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:blocked\"' | grep -qv 'packets 0 '")
      host.succeed("nft list table inet fencr-sbx | grep 'fencr:sbx:host-blocked\"' | grep -qv 'packets 0 '")
    '';

    meta.timeout = 1800;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
