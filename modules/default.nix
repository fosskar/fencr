# sealed sandboxes to run agents in: a microvm and the host units deciding
# what it reaches. a machine says what to put inside, and
# the module knows nothing about it:
#
#   fencr.sandboxes.myagent.services = [ my-agent-module ];
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
  instances = config.fencr.sandboxes;
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
  cli = import ../pkgs/cli {
    inherit lib pkgs;
    instances = resolvedInstances;
  };
  unitSets = lib.mapAttrs (_: core.hostUnits pkgs cli) resolvedInstances;
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

    # the sandbox's tables are nftables; the iptables backend cannot host them
    networking.nftables.enable = lib.mkIf (instances != { }) true;

    assertions =
      map
        (message: {
          assertion = false;
          message = "fencr: ${message}.";
        })
        (
          lib.concatMap (instance: instance.errors) (lib.attrValues resolvedInstances)
          ++ core.hostErrors resolvedInstances
        )
      ++ [
        {
          assertion = instances == { } || config.systemd.network.enable;
          message = "fencr: the bridge and tap are configured through systemd-networkd; set networking.useNetworkd = true (or systemd.network.enable = true) on this host.";
        }
      ];

    # guest memory is the hypervisor's memory and would outlive the sandbox on disk
    warnings =
      let
        plain = lib.filter (swap: !swap.randomEncryption.enable) config.swapDevices;
      in
      lib.optional (instances != { } && plain != [ ])
        "fencr: swap without randomEncryption (${
          lib.concatMapStringsSep ", " (swap: swap.device) plain
        }) can hold guest memory on disk; enable swapDevices.*.randomEncryption or use zramSwap.";

    environment.systemPackages = lib.mkIf (instances != { }) [ cli ];

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

    users.groups = forEachInstance (name: _: { ${core.jumpUserOf name} = { }; });

    users.users = forEachInstance (
      name: cfg: {
        ${core.userOf name} = {
          isSystemUser = true;
          group = "kvm";
        };
        # a way in for someone the host has no other business trusting: restrict
        # drops the pty, the shell and every forwarding, permitopen leaves one
        # destination, and a jump opens a direct-tcpip channel without a session.
        # the sandbox's own sshd is still what authenticates them.
        #
        # every sandbox gets the account, keys or not, because which accounts exist
        # may not depend on sshKeys: adminKeys is commonly root's own
        # authorizedKeys, and reading it to decide the names would ask
        # users.users for the answer it is busy computing. an account nobody is
        # authorized against is one no one can use
        ${core.jumpUserOf name} = {
          isSystemUser = true;
          group = core.jumpUserOf name;
          shell = "${pkgs.shadow}/bin/nologin";
          openssh.authorizedKeys.keys = map (key: ''restrict,permitopen="${cfg.ip}:22" ${key}'') cfg.sshKeys;
        };
      }
    );

    # 0710 keeps host users outside group kvm away from every image
    systemd.tmpfiles.rules = [
      "d /var/lib/fencr-sandboxes 0710 root kvm -"
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
        ${(core.unitsOf name).microvm} =
          core.microvmService pkgs cli instance
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

    # same-page merging lets a guest probe memory across sandboxes
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

    # the sandbox's input chain accepts first, but the main chain's drop policy
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

    # a drop in any chain is final, even after the sandbox's firewall accepted
    networking.firewall.extraForwardRules = lib.concatMapStrings (cfg: ''
      iifname "${cfg.bridge}" accept
    '') (lib.attrValues resolvedInstances);
  };
}
