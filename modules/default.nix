# sealed microvms to run agents in; a machine says what to put inside, and
# the module knows nothing about it:
#
#   fencr.vms.myagent.services = [ my-agent-module ];
#
# bridge, subnet, tap, mac and vsock cid derive from the instance's id, so
# instances never collide.
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
  core = import ./core { inherit lib; };
  resolvedInstances = lib.mapAttrs (
    name: options:
    core.resolveInstance {
      inherit name options;
      sshKeys = sshKeysOf options;
      credentials = config.fencr.credentials;
    }
  ) instances;
  unitSets = lib.mapAttrs (_: core.hostUnits pkgs) resolvedInstances;
  secretUnits = core.secretUnits pkgs config.fencr.credentials;
  reloadUnits = core.reloadUnits pkgs resolvedInstances;
  forEachInstance = f: lib.mkMerge (lib.mapAttrsToList f resolvedInstances);
  guestSystems = lib.mapAttrs (
    name: cfg:
    import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit pkgs;
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = cfg.specialArgs // {
        agentSandbox = core.guestOf resolvedInstances.${name};
      };
      modules = [
        inputs.microvm.nixosModules.microvm
        core.guestBase
      ]
      ++ cfg.services;
    }
  ) instances;
in
{
  imports = [
    ./options.nix
    ./mcp-gateway.nix
  ];

  config = {
    fencr.guestSystems = guestSystems;

    # the vm's tables are nftables; the iptables backend cannot host them
    networking.nftables.enable = lib.mkIf (instances != { }) true;

    assertions =
      map
        (message: {
          assertion = false;
          message = "fencr.vms: ${message}.";
        })
        (
          lib.concatMap (instance: instance.errors) (lib.attrValues resolvedInstances)
          ++ core.hostErrors resolvedInstances
        )
      ++ [
        {
          assertion = instances == { } || config.systemd.network.enable;
          message = "fencr.vms: the bridge and tap are configured through systemd-networkd; set networking.useNetworkd = true (or systemd.network.enable = true) on this host.";
        }
      ];

    # guest memory is the hypervisor's memory and would outlive the vm on disk
    warnings =
      let
        plain = lib.filter (swap: !swap.randomEncryption.enable) config.swapDevices;
      in
      lib.optional (instances != { } && plain != [ ])
        "fencr.vms: swap without randomEncryption (${
          lib.concatMapStringsSep ", " (swap: swap.device) plain
        }) can hold guest memory on disk; enable swapDevices.*.randomEncryption or use zramSwap."
      # the vm boundary does not cross threads of one core, which is the same
      # class of leak as the swap above and the one firecracker's
      # prod-host-setup.md names
      ++
        lib.optional (instances != { } && !(lib.elem "nosmt" config.boot.kernelParams))
          "fencr.vms: smt is on, so a guest shares a core with the host and every other vm, where a cross-thread side channel reads what the vm boundary does not stop; set boot.kernelParams = [ \"nosmt\" ] to take Firecracker's tenant-separation guidance, at the cost of the second thread of every core.";

    environment.systemPackages = lib.mkIf (instances != { }) [
      (import ../pkgs/cli {
        inherit lib pkgs;
        instances = resolvedInstances;
      })
    ];

    # any host user holding an authorized key gets in with their own identity
    programs.ssh.extraConfig = lib.concatStrings (
      lib.mapAttrsToList (
        name: cfg:
        lib.optionalString (cfg.sshKeys != [ ]) ''
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

    # 0710 keeps host users outside group kvm away from every image
    systemd.tmpfiles.rules = [
      "d /var/lib/fencr-vms 0710 root kvm -"
    ]
    ++ lib.concatMap (
      name:
      map (dir: "d ${dir} 0700 ${core.userOf name} kvm -") [
        (core.stateDirOf name)
        (core.checkpointDirOf name)
        (core.runDirOf name)
      ]
    ) (lib.attrNames instances);

    systemd.services = lib.mkMerge (
      lib.mapAttrsToList (name: instance: {
        ${(core.unitsOf name).vm} =
          core.vmService pkgs instance
            guestSystems.${name}.config.microvm.declaredRunner;
      }) resolvedInstances
      ++ map (units: units.services) (lib.attrValues unitSets)
      ++ lib.mapAttrsToList (
        name: instance:
        lib.optionalAttrs (instance.credentials != [ ]) {
          ${core.caUnitOf name} = core.caServiceOf pkgs config.networking.hostName name;
        }
      ) resolvedInstances
      ++ [
        (reloadUnits.services or { })
        (secretUnits.services or { })
      ]
    );

    systemd.sockets = lib.mkMerge (
      map (units: units.sockets) (lib.attrValues unitSets) ++ [ (secretUnits.sockets or { }) ]
    );

    systemd.timers = lib.mkMerge (map (units: units.timers) (lib.attrValues unitSets));

    systemd.paths = reloadUnits.paths or { };

    # masquerade by source address, so the module needs no uplink interface
    boot.kernel.sysctl."net.ipv4.conf.all.forwarding" = lib.mkIf (instances != { }) (
      lib.mkDefault true
    );

    # same-page merging lets a guest probe memory across vms
    # (firecracker's prod-host-setup.md)
    hardware.ksm.enable = lib.mkIf (instances != { }) false;

    # beside the main firewall, not inside it: nothing nixpkgs puts ahead of
    # extraForwardRules runs first, and the main firewall's interface rules
    # would only add ports, leaving globally open ones reachable from the bridge
    networking.nftables.tables = forEachInstance (_: cfg: core.firewallOf cfg);

    # firecracker attaches the tap by name with a virtio header and one queue
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
            Address = "${cfg.hostIp}/${toString core.prefixLength}";
            ConfigureWithoutCarrier = true;
          };
        };
        networks."11-${cfg.tap}" = {
          matchConfig.Name = cfg.tap;
          networkConfig.Bridge = cfg.bridge;
        };
      }
    );

    # the vm's input chain accepts first, but the main chain's drop policy
    # still runs after it
    networking.firewall.interfaces = forEachInstance (
      _: cfg: {
        ${cfg.bridge} = {
          allowedTCPPorts =
            cfg.hostPorts
            ++ lib.optional cfg.egress core.egressTlsPort
            ++ lib.optional cfg.dnsEgress core.egressDnsPort;
          allowedUDPPorts = lib.optional cfg.dnsEgress core.egressDnsPort;
        };
      }
    );

    # a drop in any chain is final, even after the vm's firewall accepted
    networking.firewall.extraForwardRules = lib.concatMapStrings (cfg: ''
      iifname "${cfg.bridge}" accept
    '') (lib.attrValues resolvedInstances);
  };
}
