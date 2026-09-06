self: system:

# Evaluation smoke test: a machine with one instance exercising exposed
# ports, ssh and a credential.
{ config, lib, ... }:
let
  guestConfig = config.fencr.guestSystems.sbx.config;
in
{
  imports = [ self.nixosModules.fencr ];

  assertions = [
    {
      assertion =
        builtins.attrNames (
          lib.filterAttrs (name: _: lib.hasPrefix "fencr-sbx" name) config.systemd.sockets
        ) == [
          "fencr-sbx-secrets"
        ];
      message = "nixos module check: host sockets drifted";
    }
    {
      assertion =
        guestConfig.systemd.sockets.sshd.socketConfig.ListenStream == [ "10.30.1.2:22" ]
        && guestConfig.systemd.sockets.sshd.socketConfig.FreeBind
        &&
          guestConfig.networking.firewall.allowedTCPPorts == [
            22
            22100
            33627
          ]
        && config.fencr.vms.sbx.ip == "10.30.1.2"
        && lib.hasInfix "HostName 10.30.1.2" config.programs.ssh.extraConfig
        &&
          lib.hasInfix
            ''ip daddr 10.30.1.2 tcp dport { 22, 33627, 22100 } counter accept comment "fencr:sbx:guest"''
            config.networking.nftables.tables."fencr-sbx".content;
      message = "nixos module check: the guest is not reached at its bridge address";
    }
    {
      assertion =
        config.fencr.guestSystems.sealed.config.systemd.sockets.sshd.socketConfig.ListenStream
        == [ "10.30.2.2:22" ];
      message = "nixos module check: the admin keys did not open the second vm's ssh door";
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
      assertion =
        config.systemd.services."fencr-sbx-credentials".serviceConfig.LoadCredential == [
          "anthropic:/run/secrets/anthropic"
          "ca.crt:/var/lib/fencr/ca/root.crt"
          "ca.key:/var/lib/fencr/ca/root.key"
        ]
        && config.systemd.services ? fencr-ca
        && guestConfig.networking.hosts."10.30.1.1" == [ "api.anthropic.com" ]
        && guestConfig.environment.etc."ssl/certs/ca-certificates.crt".source == "/run/fencr/ca-bundle.crt"
        && guestConfig.systemd.globalEnvironment.NIX_SSL_CERT_FILE == "/run/fencr/ca-bundle.crt";
      message = "nixos module check: credential grant did not reach the guest";
    }
    {
      assertion =
        config.fencr.guestSystems.sealed.config.systemd.network.networks."10-lan".networkConfig.DNS
        == "10.30.2.1"
        && config.systemd.services ? "fencr-sealed-egress-proxy"
        && config.networking.firewall.interfaces."br-sealed".allowedUDPPorts == [ 33053 ]
        && config.networking.firewall.interfaces."br-sealed".allowedTCPPorts == [ 33443 ];
      message = "nixos module check: allowedDomains did not make the egress proxy the resolver";
    }
    {
      assertion = config.fencr.vms.sealed.egress == "closed";
      message = "nixos module check: egress is not closed by default";
    }
    {
      assertion =
        config.systemd.sockets."fencr-sbx-secrets".socketConfig.ListenStream == "/run/fencr-sbx/vsock_5"
        &&
          config.systemd.services."fencr-sbx-secrets@".serviceConfig.LoadCredential == [
            "raw:/run/secrets/raw"
            "fencr-ca.crt:/var/lib/fencr/ca/root.crt"
          ]
        && guestConfig.systemd.services ? fencr-secrets
        && config.systemd.sockets."fencr-sbx-secrets".socketConfig.SocketUser == "fencr-sbx"
        && guestConfig.microvm.firecracker.extraConfig.vsock.uds_path == "/run/fencr-sbx/vsock";
      message = "nixos module check: the vsock sockets are not the vm's own";
    }
    {
      assertion =
        guestConfig.microvm.hypervisor == "firecracker"
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
    hostPorts = [ 443 ];
    allowedTCPDestinations = [ "192.168.1.50:8123" ];
    expose = [
      "33627"
      22100
    ];
    credentials = [ "anthropic" ];
    secrets.raw = "/run/secrets/raw";
  };

  fencr.credentials.anthropic = {
    upstream = "https://api.anthropic.com";
    header = "x-api-key";
    secretFile = "/run/secrets/anthropic";
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
