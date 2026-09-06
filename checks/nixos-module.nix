self: system:

# Evaluation smoke test: a machine with one instance exercising forwards,
# host forwards and the credential broker.
{ config, lib, ... }:
let
  guestConfig = config.fencr.guestSystems.sbx.config;
  expectedHostSockets = [
    "sbx-forward-33627"
    "sbx-forward-33628"
    "sbx-host-forward-18764"
  ];
  missingHostSockets = lib.filter (name: !(config.systemd.sockets ? ${name})) expectedHostSockets;
in
{
  imports = [ self.nixosModules.fencr ];

  assertions = [
    {
      assertion = missingHostSockets == [ ];
      message = "nixos module check: missing host sockets ${toString missingHostSockets}";
    }
    {
      assertion = guestConfig.systemd.sockets ? fencr-sshd-vsock;
      message = "nixos module check: missing guest socket fencr-sshd-vsock";
    }
    {
      assertion = guestConfig.systemd.services ? "fencr-sshd-vsock@";
      message = "nixos module check: missing guest service fencr-sshd-vsock@";
    }
    {
      assertion = guestConfig.systemd.services.sshd.wantedBy == [ ];
      message = "nixos module check: tcp sshd is still enabled";
    }
    {
      assertion = !(builtins.elem 22 guestConfig.networking.firewall.allowedTCPPorts);
      message = "nixos module check: guest firewall still opens tcp ssh";
    }
    {
      assertion = !guestConfig.system.switch.enable;
      message = "nixos module check: guest system switching is enabled";
    }
    {
      assertion = !guestConfig.nix.enable && guestConfig.environment.defaultPackages == [ ];
      message = "nixos module check: guest minimal profile drifted";
    }
    {
      assertion = config.fencr.vms.sealed.egress == "closed";
      message = "nixos module check: egress is not closed by default";
    }
    {
      assertion = builtins.elem "name=opt/io.systemd.credentials/raw,path=/run/credentials/fencr-sbx.service/raw" guestConfig.microvm.crosvm.extraArgs;
      message = "nixos module check: raw secret is not transported as a systemd credential";
    }
    {
      assertion =
        guestConfig.microvm.hypervisor == "crosvm"
        && config.systemd.services."fencr-sbx".serviceConfig.User == "fencr-sbx"
        && config.users.users."fencr-sbx".group == "kvm"
        && config.systemd.services."fencr-sbx".serviceConfig.CapabilityBoundingSet == ""
        && config.systemd.services."fencr-sbx".serviceConfig.RestrictSUIDSGID
        && guestConfig.fileSystems."/var/lib".device == "/dev/disk/by-label/fencr-state";
      message = "nixos module check: hypervisor unit drifted";
    }
    {
      assertion = !config.hardware.ksm.enable;
      message = "nixos module check: same-page merging is on";
    }
  ];

  networking.useNetworkd = true;
  boot.loader.grub.devices = [ "/dev/sda" ];
  fileSystems."/" = {
    device = "/dev/sda1";
    fsType = "ext4";
  };

  # dummy keys: never used, they only build the key-gated units
  fencr.adminKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminDummyAdminDummyAdminDummyAdminDummyAdmi check"
  ];

  fencr.vms.sbx = {
    authorizedKeys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerDummyOwnerDummyOwnerDummyOwnerDummyOwne check"
    ];
    id = 0;
    vcpu = 2;
    mem = 1024;
    dns = "9.9.9.9";
    secrets.raw = "/run/secrets/raw";
    hostPorts = [ 443 ];
    allowedTCPDestinations = [ "192.168.1.50:8123" ];
    expose = [
      "33627"
      "127.0.0.1:33628:22100"
    ];
    hostForwards = [
      {
        vsockPort = 18764;
        targetPort = 8764;
        broker.secretFile = "/run/secrets/broker-token";
      }
    ];
  };

  fencr.vms.sealed = {
    id = 1;
    vcpu = 1;
    mem = 512;
    dns = "9.9.9.9";
    allowedDomains = [
      "github.com"
      "*.github.com"
    ];
  };

  system.stateVersion = "25.11";

  nixpkgs.hostPlatform = system;
}
