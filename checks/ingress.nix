self: pkgs:
let
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  documentRoot = pkgs.writeTextDir "index.html" "fencr ingress\n";
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

      fencr.vms.sbx = {
        id = 0;
        vcpu = 1;
        mem = 768;
        authorizedKeys = [ snakeOilEd25519PublicKey ];
        secrets.raw = rawSecret;
        expose = [
          {
            listenAddress = "127.0.0.1";
            listenPort = 22100;
            guestPort = 9119;
          }
        ];
        services = [
          {
            systemd.services.ingress = {
              wantedBy = [ "multi-user.target" ];
              serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9119 --bind 127.0.0.1 --directory ${documentRoot}";
            };
          }
        ];
      };

      system.stateVersion = "25.11";
    };

    testScript = ''
      host.wait_for_unit("microvm@sbx.service", timeout=1200)
      host.wait_for_unit("sbx-forward-22100.socket")
      host.wait_until_succeeds("curl --fail --silent http://127.0.0.1:22100 | grep -Fx 'fencr ingress'", timeout=120)
      host.fail("nc -z -w 2 10.30.1.2 22")

      host.succeed("install -d -m 0700 /root/.ssh")
      host.succeed("install -m 0600 '${snakeOilEd25519PrivateKey}' /root/.ssh/id_ed25519")
      host.wait_until_succeeds("ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o 'ProxyCommand=${pkgs.socat}/bin/socat - VSOCK-CONNECT:3:22' root@sbx 'printf fencr-ssh' | grep -Fx fencr-ssh", timeout=120)
      host.succeed("ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o 'ProxyCommand=${pkgs.socat}/bin/socat - VSOCK-CONNECT:3:22' root@sbx 'cat /run/agent-secrets/raw' | grep -Fx 'fencr secret'")
    '';

    meta.timeout = 1800;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
