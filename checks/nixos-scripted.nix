self: pkgs:

# a host that keeps its own networking scripted, with dhcpcd, and turns on
# networkd only for fencr: its uplink must stay as it was, dhcpcd must leave
# the sandbox's links alone, and the sandbox's links must not hold up
# network-online. dhcpcd cannot hand its dns servers to the resolved that
# networkd brings, so the module warns until networking.nameservers is set
let
  inherit (pkgs) lib;
  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilEd25519PrivateKey
    snakeOilEd25519PublicKey
    ;
  networking = {
    imports = [ self.nixosModules.fencr ];
    systemd.network.enable = true;
    networking.interfaces.eth1 = {
      ipv4.addresses = lib.mkForce [ ];
      useDHCP = true;
    };
    fencr.sandboxes.sbx = {
      id = 0;
      vcpu = 1;
      mem = 512;
      outbound = [ ];
      authorizedKeys = [ snakeOilEd25519PublicKey ];
      services = [
        { environment.etc."fencr-scripted".text = "fencr scripted"; }
      ];
    };
    system.stateVersion = "26.11";
  };
  warned =
    extra:
    lib.any (lib.hasPrefix "fencr: networkd turns on")
      (self.inputs.nixpkgs.lib.nixosSystem {
        inherit pkgs;
        modules = [
          networking
          extra
          {
            boot.loader.grub.enable = false;
            fileSystems."/" = {
              device = "none";
              fsType = "tmpfs";
            };
          }
        ];
      }).config.warnings;
in
assert warned { };
assert !(warned { networking.nameservers = [ "192.168.1.2" ]; });
assert !(warned { networking.useNetworkd = true; });
import (pkgs.path + "/nixos/tests/make-test-python.nix")
  (_: {
    name = "fencr-nixos-scripted";

    # hands the host its address and resolver over dhcp, and answers one name
    nodes.router = {
      networking.firewall.allowedUDPPorts = [
        53
        67
      ];
      services.dnsmasq = {
        enable = true;
        resolveLocalQueries = false;
        settings = {
          interface = "eth1";
          bind-interfaces = true;
          dhcp-range = "192.168.1.100,192.168.1.150";
          dhcp-option = "option:dns-server,192.168.1.2";
          address = "/router.test/192.168.1.2";
          no-resolv = true;
        };
      };
    };

    nodes.host = {
      imports = [ networking ];
      # what the warning asks for; dhcpcd's own servers never reach resolved
      networking.nameservers = [ "192.168.1.2" ];

      virtualisation.qemu.options = [
        "-cpu"
        {
          aarch64-linux = "cortex-a72";
          x86_64-linux = "host";
        }
        .${pkgs.stdenv.hostPlatform.system}
      ];
      virtualisation.diskSize = 4096;
      virtualisation.memorySize = 2048;
    };

    testScript = ''
      start_all()
      router.wait_for_unit("dnsmasq.service")

      # the uplink stays dhcpcd's, and networkd does not touch it; the name
      # resolves through the nameservers the warning asked for
      host.wait_for_unit("dhcpcd.service")
      host.wait_until_succeeds("ip -4 addr show eth1 | grep -F 'inet 192.168.1.1'", timeout=120)
      host.succeed("networkctl list --no-legend | grep -E 'eth1 .* unmanaged'")
      host.wait_until_succeeds("getent hosts router.test | grep -F 192.168.1.2", timeout=120)

      # dhcpcd is told to leave the sandbox's links, and does
      config = host.succeed("systemctl show -p ExecStart --value dhcpcd.service | grep -o '/nix/store/[^ ;]*-dhcpcd.conf' | head -1").strip()
      host.succeed(f"grep -E '^denyinterfaces .*br-sbx .*tap-sbx' {config}")
      host.wait_for_unit("fencr-sbx.service")
      host.wait_until_succeeds("networkctl list --no-legend | grep -E 'br-sbx .* configured'", timeout=120)
      host.succeed("test \"$(ip -4 -o addr show br-sbx | wc -l)\" = 1")
      host.succeed("ip -4 addr show br-sbx | grep -F 'inet 10.11.0.1/'")

      # networkd manages no uplink here, and the sandbox's links are not one
      host.succeed("systemctl show -p Result --value systemd-networkd-wait-online.service | grep -Fx success")

      host.succeed("install -d -m 0700 /root/.ssh")
      host.succeed("install -m 0600 '${snakeOilEd25519PrivateKey}' /root/.ssh/id_ed25519")
      host.wait_until_succeeds("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sbx cat /etc/fencr-scripted | grep -Fx 'fencr scripted'", timeout=300)
    '';

    meta.timeout = 1200;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
