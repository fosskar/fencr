# sealed microvms to run agents in. each instance provides the environment —
# private bridge, nat to the internet, a firewall that drops every private
# range, a persistent /var/lib and room to install into — and knows nothing
# about which agent runs there. a machine says what to put inside:
#
#   fencr.vms.myagent.services = [ my-agent-module ];
#
# per-instance networking (bridge, subnet, tap, mac, vsock cid) derives from
# the instance's id, so instances never collide. the vm's address on its
# bridge is where its sshd and its exposed ports answer.
{ inputs }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  instances = config.fencr.vms;
  sshKeysOf = cfg: config.fencr.adminKeys ++ cfg.authorizedKeys;
  core = import ../core { inherit lib; };
  resolvedInstances = lib.mapAttrs (
    name: options:
    core.resolveInstance {
      inherit name options;
      sshKeys = sshKeysOf options;
      credentials = config.fencr.credentials;
    }
  ) instances;
  unitSets = lib.mapAttrs (_: core.hostUnits pkgs) resolvedInstances;
  forEachInstance = f: lib.mkMerge (lib.mapAttrsToList f resolvedInstances);
  # the guest evaluates against the host's nixpkgs
  guestSystems = lib.mapAttrs (
    name: cfg:
    import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit pkgs;
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = cfg.specialArgs // {
        agentSandbox = resolvedInstances.${name}.guest;
      };
      modules = [
        inputs.microvm.nixosModules.microvm
        (core.guestBase inputs.microvm)
      ]
      ++ cfg.services;
    }
  ) instances;
in
{
  imports = [ ./options.nix ];

  config = {
    fencr.guestSystems = guestSystems;

    # the vm's firewall is written in nftables; the iptables firewall cannot host it
    networking.nftables.enable = lib.mkIf (instances != { }) true;

    assertions =
      map
        (message: {
          assertion = false;
          message = "fencr.vms: ${message}.";
        })
        (
          lib.concatMap (instance: instance.errors) (lib.attrValues resolvedInstances)
          ++ core.fleetErrors resolvedInstances
        )
      ++ [
        {
          assertion = instances == { } || config.systemd.network.enable;
          message = "fencr.vms: the bridge and tap are configured through systemd-networkd; set networking.useNetworkd = true (or systemd.network.enable = true) on this host.";
        }
      ];

    environment.systemPackages = lib.mkIf (instances != { }) [
      (import ../cli.nix {
        inherit lib pkgs;
        instances = resolvedInstances;
        units = unitSets;
      })
    ];

    # `ssh <vm-name>` reaches the guest's sshd at its bridge address; any
    # host user holding an authorized key gets in with their own identity
    programs.ssh.extraConfig = lib.concatStrings (
      lib.mapAttrsToList (
        name: cfg:
        lib.optionalString (cfg.guest.sshKeys != [ ]) ''
          Host ${name}
            HostName ${cfg.ip}
            User root
            StrictHostKeyChecking accept-new
        ''
      ) resolvedInstances
    );

    users.users = forEachInstance (
      name: _: {
        ${core.userOf name} = {
          isSystemUser = true;
          group = "kvm";
        };
      }
    );

    # the parent keeps host users outside group kvm away from every image;
    # the state tree and the vsock sockets admit the vm's user alone
    systemd.tmpfiles.rules = [
      "d /var/lib/fencr-vms 0710 root kvm -"
    ]
    ++ map (name: "d ${core.stateDirOf name} 0700 ${core.userOf name} kvm -") (lib.attrNames instances)
    ++ map (name: "d ${core.runDirOf name} 0700 ${core.userOf name} kvm -") (lib.attrNames instances);

    systemd.services = lib.mkMerge (
      lib.mapAttrsToList (name: instance: {
        ${(core.unitsOf name).vm} =
          core.vmService pkgs instance
            guestSystems.${name}.config.microvm.declaredRunner;
      }) resolvedInstances
      ++ map (units: units.services) (lib.attrValues unitSets)
      ++
        lib.optional (lib.any (instance: instance.credentials != [ ]) (lib.attrValues resolvedInstances))
          {
            ${core.caUnit} = core.caService pkgs config.networking.hostName;
          }
    );

    systemd.sockets = lib.mkMerge (map (units: units.sockets) (lib.attrValues unitSets));

    # masquerade by the vm's source address instead of networking.nat, so
    # the module needs no knowledge of the host's uplink interface
    boot.kernel.sysctl."net.ipv4.conf.all.forwarding" = lib.mkIf (instances != { }) (
      lib.mkDefault true
    );

    # same-page merging lets a guest probe memory across vms
    hardware.ksm.enable = lib.mkIf (instances != { }) false;

    # the vm's firewall tables stand beside the main firewall rather than inside it, so
    # nothing nixpkgs puts ahead of extraForwardRules (icmpv6, dnat) runs
    # before them, and the host keeps its own forward policy. the main
    # firewall's interface rules only add ports, so globally open ones (sshd
    # at least) would stay reachable from the bridges; the vm's input chain
    # runs first and admits hostPorts and the egress proxy, nothing else
    networking.nftables.tables = forEachInstance (_: cfg: core.firewallOf cfg);

    # firecracker attaches the tap by name with a virtio header and one queue, so
    # it is persistent and its flags match; group kvm lets the vm unit open it
    systemd.network = forEachInstance (
      _name: cfg: {
        netdevs."10-${cfg.bridge}".netdevConfig = {
          Name = cfg.bridge;
          Kind = "bridge";
        };
        netdevs."11-${cfg.tap}" = {
          netdevConfig = {
            Name = cfg.tap;
            Kind = "tap";
          };
          tapConfig = {
            Group = "kvm";
            VNetHeader = true;
          };
        };
        networks."10-${cfg.bridge}" = {
          matchConfig.Name = cfg.bridge;
          networkConfig = {
            Address = "${cfg.hostIp}/${toString cfg.prefixLength}";
            ConfigureWithoutCarrier = true;
          };
        };
        networks."11-${cfg.tap}" = {
          matchConfig.Name = cfg.tap;
          networkConfig.Bridge = cfg.bridge;
        };
      }
    );

    # its input chain accepts first, but the main chain's drop policy
    # still runs after it, so the egress proxy's ports open there too
    networking.firewall.interfaces = forEachInstance (
      _: cfg: {
        ${cfg.bridge} = {
          allowedTCPPorts = cfg.hostPorts ++ lib.optional cfg.proxy core.proxyTlsPort;
          allowedUDPPorts = lib.optional cfg.dnsProxy core.proxyDnsPort;
        };
      }
    );

    # with filterForward the main forward chain drops by policy, and a drop
    # in any chain is final even after the vm's firewall accepted
    networking.firewall.extraForwardRules = lib.concatMapStrings (cfg: ''
      iifname "${cfg.bridge}" accept
    '') (lib.attrValues resolvedInstances);
  };
}
