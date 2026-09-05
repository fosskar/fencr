self: pkgs:

# Boots the flakelet surface: its units go onto a plain host, and the same
# ingress path as checks/ingress.nix is driven through them (the exposed
# port, ssh over vsock, a staged secret). Building this check runs the vm.
let
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  rawSecret = pkgs.writeText "fencr-test-secret" "fencr secret\n";
  # the payload is a store path handed to the flakelet as a string, and
  # importing it at eval time drops the string's context. anything it names
  # by interpolation would not be a dependency of the guest system, so the
  # document it serves is built inside the guest instead of referenced.
  ingressModule = pkgs.writeText "fencr-test-ingress.nix" ''
    { pkgs, ... }:
    {
      environment.etc."fencr-ingress/index.html".text = "fencr ingress\n";
      systemd.services.ingress = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "''${pkgs.python3}/bin/python3 -m http.server 9119 --bind 127.0.0.1 --directory /etc/fencr-ingress";
      };
    }
  '';
  module = self.flakelets.default { types = null; };
  result = module.impl {
    options = {
      id = 0;
      vcpu = 1;
      mem = 768;
      dns = "9.9.9.9";
      egress = "closed";
      allowedDomains = [ ];
      authorizedKeys = [ snakeOilEd25519PublicKey ];
      secrets.raw = "${rawSecret}";
      allowedTCPDestinations = [ ];
      expose = [
        {
          listenAddress = "127.0.0.1";
          listenPort = 22100;
          guestPort = 9119;
        }
      ];
      hostForwards = [ ];
      hostPorts = [ ];
      guestModules = [ "${ingressModule}" ];
    };
    inputs = {
      nixpkgs = {
        inherit pkgs;
        inherit (pkgs) lib;
      };
      flakelet = {
        name = "sbx";
        storePath = path: path;
        contracts = { };
        extraModules = [ ];
      };
    };
  };
in
import (pkgs.path + "/nixos/tests/make-test-python.nix")
  (
    { pkgs, ... }:
    {
      name = "fencr-flakelet-boot";

      nodes.host = {
        virtualisation.qemu.options = [
          "-cpu"
          {
            aarch64-linux = "cortex-a72";
            x86_64-linux = "kvm64,+svm,+vmx";
          }
          .${pkgs.stdenv.hostPlatform.system}
        ];
        virtualisation.diskSize = 4096;

        # the flakelet surface installs its ruleset with a store path, so the
        # host has no nft of its own; the check reads the seal with one
        environment.systemPackages = [
          pkgs.curl
          pkgs.openssh
          pkgs.nftables
        ];

        systemd.services = result.services;
        systemd.sockets = result.sockets;

        system.stateVersion = "25.11";
      };

      testScript = ''
        ssh = "ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o 'ProxyCommand=${pkgs.socat}/bin/socat - VSOCK-CONNECT:3:22' root@sbx"

        host.wait_for_unit("sbx-virtiofsd.service", timeout=1200)
        host.wait_for_unit("sbx.service", timeout=1200)
        # the vm unit must come up once, not survive on a restart
        host.succeed("test \"$(systemctl show sbx.service -p NRestarts --value)\" = 0")

        # the vsock door first: it belongs to the guest base, so it proves the
        # transport before anything the payload provides
        host.succeed("install -d -m 0700 /root/.ssh")
        host.succeed("install -m 0600 '${snakeOilEd25519PrivateKey}' /root/.ssh/id_ed25519")
        host.wait_until_succeeds(f"{ssh} 'printf fencr-ssh' | grep -Fx fencr-ssh", timeout=300)
        host.succeed(f"{ssh} 'cat /run/agent-secrets/raw' | grep -Fx 'fencr secret'", timeout=60)

        # the state share is writable and lands on the host's tree
        host.succeed(f"{ssh} 'touch /var/lib/fencr-state-survives'", timeout=60)
        host.succeed("test -e /var/lib/fencr-vms/sbx/fencr-state-survives")

        # the payload module ran inside the vm and its port reaches the host
        # through the whole chain: host socket, relay, vsock, guest proxy
        host.succeed(f"{ssh} 'systemctl is-system-running --wait'", timeout=180)
        host.wait_for_unit("fwd-22100.socket")
        host.wait_until_succeeds("curl --fail --silent http://127.0.0.1:22100 | grep -Fx 'fencr ingress'", timeout=120)

        host.succeed("nft list table inet fencr-sbx | grep -q 'fencr:sbx:blocked'")
        host.succeed("systemctl show sbx.service -p MemoryMax --value | grep -qv infinity")
      '';

      meta.timeout = 1800;
    }
  )
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
