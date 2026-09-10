self: system:

# builds a host with two vms: exposed ports, ssh, a credential and a raw
# secret on one, a domain allowlist on the other
{ config, lib, ... }:
let
  guestConfig = config.fencr.guestSystems.sbx.config;
in
{
  imports = [ self.nixosModules.fencr ];

  assertions = [
    {
      assertion =
        guestConfig.systemd.sockets.sshd.socketConfig.ListenStream == [ "10.11.0.2:22" ]
        && guestConfig.systemd.sockets.sshd.socketConfig.FreeBind
        &&
          guestConfig.networking.firewall.allowedTCPPorts == [
            22
            22100
            33627
          ]
        && config.fencr.vms.sbx.ip == "10.11.0.2"
        && lib.hasInfix "HostName 10.11.0.2" config.programs.ssh.extraConfig;
      message = "nixos module check: the guest is not reached at its bridge address";
    }
    {
      assertion =
        config.fencr.guestSystems.sealed.config.systemd.sockets.sshd.socketConfig.ListenStream
        == [ "10.11.1.2:22" ];
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
        config.systemd.services ? fencr-ca
        && config.systemd.services ? fencr-sbx-credentials
        && guestConfig.networking.hosts."10.11.0.1" == [ "api.anthropic.com" ]
        && guestConfig.environment.etc."ssl/certs/ca-certificates.crt".source == "/run/fencr/ca-bundle.crt"
        && guestConfig.systemd.globalEnvironment.NIX_SSL_CERT_FILE == "/run/fencr/ca-bundle.crt";
      message = "nixos module check: credential grant did not reach the guest";
    }
    {
      assertion =
        config.fencr.credentials.anthropic.upstream == "https://api.anthropic.com"
        && config.fencr.credentials.anthropic.header == "x-api-key"
        && config.fencr.credentials.sbx-openrouter.provider == "openrouter"
        && config.fencr.credentials.sbx-openrouter.upstream == "https://openrouter.ai"
        && config.fencr.credentials.sbx-openrouter.header == "X-Custom"
        && config.fencr.credentials.local.provider == null;
      message = "nixos module check: provider defaults did not apply";
    }
    {
      assertion =
        config.fencr.guestSystems.sealed.config.systemd.network.networks."10-lan".networkConfig.DNS
        == "10.11.1.1"
        && config.systemd.services ? "fencr-sealed-egress-proxy"
        && config.networking.firewall.interfaces."br-sealed".allowedUDPPorts == [ 33053 ]
        && config.networking.firewall.interfaces."br-sealed".allowedTCPPorts == [ 33443 ]
        &&
          config.networking.firewall.interfaces."br-sbx".allowedTCPPorts == [
            53
            443
            33443
          ];
      message = "nixos module check: outbound domains did not make the egress proxy the resolver";
    }
    {
      assertion =
        guestConfig.systemd.network.networks."10-lan".networkConfig.DNS == "10.11.0.1"
        && config.services.resolved.settings.Resolve.DNSStubListenerExtra == [ "10.11.0.1" ]
        && config.networking.firewall.interfaces."br-sbx".allowedUDPPorts == [ 53 ];
      message = "nixos module check: open egress did not put the host's resolver on the bridge";
    }
    {
      assertion =
        let
          rules = config.networking.nftables.tables.fencr-sealed.content;
        in
        lib.hasInfix ''counter drop comment "fencr:sealed:blocked"'' rules
        && !lib.hasInfix ''counter accept comment "fencr:sealed:internet"'' rules;
      message = "nixos module check: domain grants opened internet access";
    }
    {
      assertion =
        config.systemd.sockets ? fencr-sbx-secrets
        &&
          config.systemd.services."fencr-sbx-secrets@".serviceConfig.LoadCredential == [
            "raw:/run/secrets/raw"
            "fencr-ca.crt:/var/lib/fencr/ca/root.crt"
          ]
        && guestConfig.systemd.services ? fencr-secrets
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
        && config.systemd.services."fencr-sbx".serviceConfig.PrivateIPC
        && guestConfig.fileSystems."/".device == "/dev/disk/by-label/fencr-state";
      message = "nixos module check: hypervisor unit drifted";
    }
    {
      assertion =
        let
          drives = guestConfig.microvm.firecracker.extraConfig.drives;
          state = lib.findFirst (drive: drive.path_on_host == "/var/lib/fencr-vms/sbx/state.img") null drives;
        in
        map (drive: drive.path_on_host) drives == [
          guestConfig.microvm.storeDisk
          "/var/lib/fencr-vms/sbx/state.img"
        ]
        && state.cache_type == "Writeback"
        && !state.is_read_only
        && (lib.head drives).is_read_only
        && guestConfig.microvm.firecracker.extraConfig ? entropy;
      message = "nixos module check: the guest's drives drifted from the runner's";
    }
    {
      assertion = !config.hardware.ksm.enable;
      message = "nixos module check: same-page merging is on";
    }
    {
      assertion =
        let
          swap = lib.filter (lib.hasPrefix "fencr.vms: swap") config.warnings;
        in
        lib.length swap == 1
        && lib.hasInfix "(/dev/sda2)" (lib.head swap)
        && !lib.hasInfix "sda3" (lib.head swap);
      message = "nixos module check: the swap warning names the wrong devices";
    }
  ];

  # one plain swap partition, which the module warns about, and one with a
  # per-boot random key, which it accepts
  swapDevices = [
    { device = "/dev/sda2"; }
    {
      device = "/dev/sda3";
      randomEncryption.enable = true;
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
    outbound = [
      "internet"
      "host:443"
      "192.168.1.50:8123"
    ];
    inbound = [
      33627
      22100
    ];
    credentials = [ "anthropic" ];
    secrets.raw = "/run/secrets/raw";
  };

  fencr.credentials = {
    anthropic.secretFile = "/run/secrets/anthropic";
    sbx-openrouter = {
      provider = "openrouter";
      header = "X-Custom";
      secretFile = "/run/secrets/openrouter";
    };
    local = {
      upstream = "http://127.0.0.1:8764";
      domain = "local.fencr";
      secretFile = "/run/secrets/local";
    };
  };

  fencr.vms.sealed = {
    outbound = [
      "github.com"
      "*.github.com"
    ];
  };

  system.stateVersion = "25.11";

  nixpkgs.hostPlatform = system;
}
