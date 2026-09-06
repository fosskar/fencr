# sealed microvms to run agents in. each instance provides the environment —
# private bridge, nat to the internet, a firewall that drops every private
# range, a persistent /var/lib and room to install into — and knows nothing
# about which agent runs there. a machine says what to put inside:
#
#   fencr.vms.myagent.services = [ my-agent-module ];
#
# per-instance networking (bridge, subnet, tap, mac, vsock cid) derives from
# the instance's id, so instances never collide. reaching a service inside is
# this module's business too: `forwards` maps a host endpoint to a guest port
# and the whole path — socket unit, vsock connector, guest-side proxy — lives
# here, so callers never name a transport.
{ inputs }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  hostConfig = config;
  instances = config.fencr.vms;
  sshKeysOf = cfg: config.fencr.adminKeys ++ cfg.authorizedKeys;
  core = import ./core.nix { inherit lib; };
  resolvedInstances = lib.mapAttrs (
    name: options:
    core.resolveInstance {
      inherit name options;
      sshKeys = sshKeysOf options;
    }
  ) instances;
  unitSets = lib.mapAttrs (
    name: instance:
    core.hostUnits pkgs instance {
      vmUnit = "microvm@${name}.service";
      forwardName = forward: "${name}-forward-${toString forward.listenPort}";
      hostForwardName = forward: "${name}-host-forward-${toString forward.vsockPort}";
      proxyName = "${name}-egress-proxy";
      brokerName = forward: "${name}-broker-${toString forward.vsockPort}";
    }
  ) resolvedInstances;
  exposeType = lib.types.coercedTo lib.types.str core.parseExpose (
    lib.types.submodule {
      options = {
        listenAddress = lib.mkOption {
          type = lib.types.str;
          default = "127.0.0.1";
        };
        listenPort = lib.mkOption { type = lib.types.port; };
        guestPort = lib.mkOption { type = lib.types.port; };
      };
    }
  );
  destinationType = lib.types.coercedTo lib.types.str core.parseDestination (
    lib.types.submodule {
      options = {
        address = lib.mkOption { type = lib.types.str; };
        port = lib.mkOption { type = lib.types.port; };
      };
    }
  );
  forEachInstance = f: lib.mkMerge (lib.mapAttrsToList f resolvedInstances);
in
{
  imports = [ inputs.microvm.nixosModules.host ];

  options.fencr.adminKeys = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    description = ''
      public keys authorized as root in every vm.
      host root can always reach a vm regardless (it owns the hypervisor,
      the state tree and the console); this only makes that access ssh.
    '';
  };

  options.fencr.vms = lib.mkOption {
    default = { };
    description = "sealed agent microvms, keyed by vm name.";
    type = lib.types.attrsOf (
      lib.types.submodule {
        options = {
          id = lib.mkOption {
            type = lib.types.ints.between 0 8;
            description = "unique instance index; derives bridge, subnet, tap, mac and vsock cid.";
          };

          services = lib.mkOption {
            type = lib.types.listOf lib.types.raw;
            default = [ ];
            description = "nixos modules to run inside the vm.";
          };

          authorizedKeys = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = ''
              public keys authorized as root in this vm — the owner tier.
              a vm belongs to whoever holds these keys; no host account
              needed. without adminKeys and authorizedKeys the vm has no
              ssh door at all.
            '';
          };

          specialArgs = lib.mkOption {
            type = lib.types.attrsOf lib.types.raw;
            default = { };
            description = "extra specialArgs handed to the guest's module system.";
          };

          vcpu = lib.mkOption {
            type = lib.types.int;
            default = core.defaults.vcpu;
          };
          mem = lib.mkOption {
            type = lib.types.int;
            default = core.defaults.mem;
            description = "guest memory ceiling; free page reporting returns unused memory to the host.";
          };
          memoryMax = lib.mkOption {
            type = lib.types.str;
            default = core.defaults.memoryMax;
            description = "hard cap on the whole vm unit, enforced by the host; guest ceiling plus hypervisor overhead.";
          };
          cpuQuota = lib.mkOption {
            type = lib.types.str;
            default = core.defaults.cpuQuota;
          };
          secrets = lib.mkOption {
            type = lib.types.attrsOf lib.types.path;
            default = { };
            description = ''
              host files passed through qemu fw_cfg and materialized in the
              vm's volatile /run/agent-secrets. guest root can read these raw
              values; use a brokered hostForward when the value must remain
              outside the vm.
            '';
          };

          egress = lib.mkOption {
            type = lib.types.enum [
              "open"
              "closed"
            ];
            default = core.defaults.egress;
            description = ''
              "open": internet and dns reachable, private ranges sealed.
              "closed": nothing reachable beyond allowedTCPDestinations,
              dns included. this is the default.
            '';
          };

          allowedDomains = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            example = lib.literalExpression ''[ "github.com" "*.github.com" ]'';
            description = ''
              domains reachable through the egress proxy; fnmatch patterns,
              so "*.github.com" does not match the bare "github.com" — list
              both. implies egress = "closed": the proxy becomes the only
              road out, enforced on the CONNECT hostname without
              interception.
            '';
          };

          allowedTCPDestinations = lib.mkOption {
            type = lib.types.listOf destinationType;
            default = [ ];
            description = ''
              IPv4 TCP destinations reachable from the vm, as
              "<address>:<port>" or { address; port; }. each entry is an
              explicit exception to the default closed egress policy.
            '';
          };

          expose = lib.mkOption {
            type = lib.types.listOf exposeType;
            default = [ ];
            example = lib.literalExpression ''[ "33627" ]'';
            description = ''
              guest loopback ports exposed on host endpoints over vsock.
              listenAddress narrows tcp clients only: vsock connect needs no
              privilege, so every host account can also reach the guest
              port directly through the vm's cid.
            '';
          };

          hostForwards = lib.mkOption {
            type = lib.types.listOf (
              lib.types.submodule {
                options = {
                  vsockPort = lib.mkOption { type = lib.types.port; };
                  targetPort = lib.mkOption { type = lib.types.port; };
                  broker = lib.mkOption {
                    type = lib.types.nullOr (
                      lib.types.submodule {
                        options = {
                          header = lib.mkOption {
                            type = lib.types.str;
                            default = "Authorization";
                          };
                          secretFile = lib.mkOption {
                            type = lib.types.path;
                            description = "file with the raw header value; never enters the vm.";
                          };
                        };
                      }
                    );
                    default = null;
                    description = ''
                      credential broker for this forward: the guest speaks
                      plain http, the broker injects the header on the host
                      side of the vsock hop.
                    '';
                  };
                };
              }
            );
            default = [ ];
            description = "guest loopback ports forwarded to host ports over vsock.";
          };

          hostPorts = lib.mkOption {
            type = lib.types.listOf lib.types.port;
            default = [ ];
            description = "host TCP ports reachable from the vm over the bridge.";
          };

          dns = lib.mkOption {
            type = lib.types.str;
            default = builtins.head hostConfig.networking.nameservers;
            defaultText = "the host's first resolver";
          };
        };
      }
    );
  };

  config = {
    boot.kernelModules = lib.mkIf (instances != { }) [ "vhost_vsock" ];

    # the seal is written in nftables; the iptables firewall cannot host it
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
      (import ./cli.nix {
        inherit lib pkgs;
        instances = resolvedInstances;
        units = unitSets;
      })
    ];

    # `ssh <vm-name>` reaches the guest's vsock sshd; vsock connect is
    # unprivileged, so any host user holding an authorized key gets in
    # with their own identity. no bridge ip, no network listener anywhere
    programs.ssh.extraConfig = lib.concatStrings (
      lib.mapAttrsToList (
        name: cfg:
        lib.optionalString (cfg.guest.sshKeys != [ ]) ''
          Host ${name}
            User root
            ProxyCommand ${pkgs.socat}/bin/socat - VSOCK-CONNECT:${toString cfg.cid}:22
            StrictHostKeyChecking accept-new
        ''
      ) resolvedInstances
    );

    systemd.services = lib.mkMerge (
      [
        # microvm.nix upstream script trips SC2046
        { "microvm-set-booted@".enableStrictShellChecks = false; }
      ]
      ++ lib.mapAttrsToList (name: instance: {
        "${name}-vm-state" = {
          description = "state dir for the ${name} vm";
          wantedBy = [ "microvm@${name}.service" ];
          before = [ "microvm@${name}.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = false;
          };
          script = ''
            install -d -m 0700 ${core.stateDirOf name}
          '';
        };

        # microvm.nix owns the unit's user and working directory; the caps,
        # secrets and confinement come from core like on the flakelet surface
        "microvm@${name}".serviceConfig = core.vmServiceConfig {
          inherit instance;
          writablePaths = [ "${config.microvm.stateDir}/${name}" ];
        };
      }) resolvedInstances
      ++ map (units: units.services) (lib.attrValues unitSets)
    );

    systemd.sockets = lib.mkMerge (map (units: units.sockets) (lib.attrValues unitSets));

    microvm.vms = lib.mapAttrs (name: cfg: {
      autostart = true;
      specialArgs = cfg.specialArgs // {
        agentSandbox = unitSets.${name}.guest;
      };
      config =
        { ... }:
        {
          imports = [ core.guestBase ] ++ cfg.services;
        };
    }) instances;

    # masquerade by the vm's source address instead of networking.nat, so
    # the module needs no knowledge of the host's uplink interface
    boot.kernel.sysctl."net.ipv4.conf.all.forwarding" = lib.mkDefault true;

    # the seal tables stand beside the main firewall rather than inside it, so
    # nothing nixpkgs puts ahead of extraForwardRules (icmpv6, dnat) runs
    # before the seal, and the host keeps its own forward policy. the main
    # firewall's interface rules only add ports, so globally open ones (sshd
    # at least) would stay reachable from the bridges; the seal's input chain
    # runs first and admits only the bridge's declared allowedTCPPorts
    networking.nftables.tables = forEachInstance (
      _: cfg:
      (core.firewallOf (
        cfg
        // {
          hostPorts = lib.unique config.networking.firewall.interfaces.${cfg.bridge}.allowedTCPPorts;
        }
      )).tables
    );

    systemd.network = forEachInstance (
      _name: cfg: {
        netdevs."10-${cfg.bridge}".netdevConfig = {
          Name = cfg.bridge;
          Kind = "bridge";
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

    networking.firewall.interfaces = forEachInstance (
      _: cfg: {
        ${cfg.bridge}.allowedTCPPorts = cfg.hostPorts;
      }
    );
  };
}
