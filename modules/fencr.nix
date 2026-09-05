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
  adminCfg = config.fencr.admin;
  core = import ./core.nix { inherit lib; };
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
  forwardUnit = name: forward: "${name}-forward-${toString forward.listenPort}";
  hostForwardUnit = name: forward: "${name}-host-forward-${toString forward.vsockPort}";
  brokerUnit = name: forward: "${name}-broker-${toString forward.vsockPort}";
  proxyOf = cfg: if cfg.allowedDomains == [ ] then null else { port = core.proxyPortOf cfg; };
  hostForwardsOf =
    cfg:
    cfg.hostForwards
    ++ lib.optional (proxyOf cfg != null) {
      vsockPort = (proxyOf cfg).port;
      targetPort = (proxyOf cfg).port;
      broker = null;
    };
  brokeredOf = cfg: lib.filter (forward: forward.broker != null) cfg.hostForwards;
  forEachInstance = f: lib.mkMerge (lib.mapAttrsToList f instances);
in
{
  imports = [ inputs.microvm.nixosModules.host ];

  options.fencr.admin = {
    # root's client identity into the vms and the public key the guests
    # authorize. with the defaults left null there is no ssh path into a
    # guest beyond the serial console.
    identityFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "private key path for the host's `ssh <vm-name>` alias into the vms.";
    };
    publicKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "public key authorized as root inside every vm.";
    };
  };

  options.fencr.forwardEndpoints = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    internal = true;
    description = "host endpoints claimed by sandbox forwards, as address:port.";
  };

  options.fencr.vms = lib.mkOption {
    default = { };
    description = "sealed agent microvms, keyed by vm name.";
    type = lib.types.attrsOf (
      lib.types.submodule (
        { name, config, ... }:
        {
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

            specialArgs = lib.mkOption {
              type = lib.types.attrsOf lib.types.raw;
              default = { };
              description = "extra specialArgs handed to the guest's module system.";
            };

            vcpu = lib.mkOption {
              type = lib.types.int;
              default = 4;
            };
            mem = lib.mkOption {
              type = lib.types.int;
              default = 4096;
              description = "guest memory ceiling; free page reporting returns unused memory to the host.";
            };
            memoryMax = lib.mkOption {
              type = lib.types.str;
              default = "4608M";
              description = "hard cap on the whole vm unit, enforced by the host; guest ceiling plus hypervisor overhead.";
            };
            cpuQuota = lib.mkOption {
              type = lib.types.str;
              default = "400%";
            };
            secrets = lib.mkOption {
              type = lib.types.attrsOf lib.types.path;
              default = { };
              description = ''
                host files to stage and share read-only into the vm, keyed by
                the name they get under /run/agent-secrets. staged as copies so
                the vm never sees the host's secret tree wholesale.
              '';
            };

            egress = lib.mkOption {
              type = lib.types.enum [
                "open"
                "closed"
              ];
              default = if config.allowedDomains == [ ] then "open" else "closed";
              defaultText = "closed when allowedDomains is set, otherwise open";
              description = ''
                "open": internet and dns reachable, private ranges sealed.
                "closed": nothing reachable beyond allowedTCPDestinations,
                dns included.
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
                private IPv4 TCP destinations reachable from the vm, as
                "<address>:<port>" or { address; port; }. internet egress is
                open by default; this list only opens private ranges.
              '';
            };

            expose = lib.mkOption {
              type = lib.types.listOf exposeType;
              default = [ ];
              example = lib.literalExpression ''[ "33627" ]'';
              description = "guest loopback ports exposed on host endpoints over vsock.";
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
                            port = lib.mkOption {
                              type = lib.types.port;
                              description = "host loopback port the broker listens on.";
                            };
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

            bridge = lib.mkOption {
              type = lib.types.str;
              default = core.bridgeOf name;
            };
            hostIp = lib.mkOption {
              type = lib.types.str;
              default = core.hostIpOf config;
              description = "the host's address on the bridge, and the vm's gateway.";
            };
            ip = lib.mkOption {
              type = lib.types.str;
              default = core.ipOf config;
            };
            prefixLength = lib.mkOption {
              type = lib.types.int;
              default = 24;
            };
            dns = lib.mkOption {
              type = lib.types.str;
              default = builtins.head hostConfig.networking.nameservers;
              defaultText = "the host's first resolver";
            };
          };
        }
      )
    );
  };

  config = {
    boot.kernelModules = lib.mkIf (instances != { }) [ "vhost_vsock" ];

    # the seal is written in nftables; the iptables firewall cannot host it
    networking.nftables.enable = lib.mkIf (instances != { }) true;

    assertions = [
      {
        assertion = lib.allUnique (lib.mapAttrsToList (_: cfg: cfg.id) instances);
        message = "fencr.vms: instance ids must be unique.";
      }
      {
        # IFNAMSIZ caps interface names at 15 chars
        assertion = lib.all (name: lib.stringLength (core.tapOf name) <= 15) (lib.attrNames instances);
        message = "fencr.vms: vm names must be at most ${
          toString (15 - lib.stringLength (core.tapOf ""))
        } chars, so tap and bridge names fit IFNAMSIZ.";
      }
      {
        assertion = lib.allUnique config.fencr.forwardEndpoints;
        message = "fencr.vms: host listen endpoints must be unique across instances.";
      }
      {
        assertion = lib.all (cfg: cfg.allowedDomains == [ ] || cfg.egress == "closed") (
          lib.attrValues instances
        );
        message = "fencr.vms: allowedDomains requires egress = \"closed\"; with open egress the proxy filter is decoration.";
      }
    ];

    fencr.forwardEndpoints =
      lib.concatLists (
        lib.mapAttrsToList (
          _: cfg: map (forward: "${forward.listenAddress}:${toString forward.listenPort}") cfg.expose
        ) instances
      )
      ++ lib.concatLists (
        lib.mapAttrsToList (
          _: cfg: map (forward: "127.0.0.1:${toString forward.broker.port}") (brokeredOf cfg)
        ) instances
      );

    # root on the host is the only thing that can reach the bridges, so
    # `ssh <vm-name>` from the host logs in as root
    programs.ssh.extraConfig = lib.mkIf (adminCfg.identityFile != null) (
      lib.concatStrings (
        lib.mapAttrsToList (name: cfg: ''
          Host ${name} ${cfg.ip}
            HostName ${cfg.ip}
            User root
            IdentityFile ${adminCfg.identityFile}
            IdentitiesOnly yes
            StrictHostKeyChecking accept-new
        '') instances
      )
    );

    systemd.services = lib.mkMerge (
      [
        # microvm.nix upstream script trips SC2046
        { "microvm-set-booted@".enableStrictShellChecks = false; }
      ]
      ++ lib.mapAttrsToList (name: cfg: {
        "${name}-vm-secrets" = lib.mkIf (cfg.secrets != { }) {
          description = "stage secrets for the ${name} vm";
          wantedBy = [ "microvm@${name}.service" ];
          before = [ "microvm@${name}.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = false;
          };
          script = ''
            install -d -m 0700 /var/lib/fencr/${name}
            install -d -m 0755 ${core.secretsDirOf name}
            ${lib.concatStringsSep "\n" (
              lib.mapAttrsToList (
                secretName: src: "install -m 0400 ${src} ${core.secretsDirOf name}/${secretName}"
              ) cfg.secrets
            )}
          '';
        };

        "${name}-vm-state" = {
          description = "state dir for the ${name} vm";
          wantedBy = [ "microvm@${name}.service" ];
          before = [ "microvm@${name}.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = false;
          };
          script = ''
            install -d -m 0755 ${core.stateDirOf name}
          '';
        };

        # the vm cannot outgrow this even if an agent misbehaves; the in-vm
        # balloon hands unused memory back below the cap
        "microvm@${name}".serviceConfig = {
          MemoryMax = cfg.memoryMax;
          CPUQuota = cfg.cpuQuota;
          CPUWeight = 20;
        };
      }) instances
      ++ lib.concatLists (
        lib.mapAttrsToList (
          name: cfg:
          map (forward: {
            "${forwardUnit name forward}@" = {
              description = "forward to ${name} guest port ${toString forward.guestPort}";
              after = [ "microvm@${name}.service" ];
              requires = [ "microvm@${name}.service" ];
              # per-connection instances must not pile up in failed state
              unitConfig.CollectMode = "inactive-or-failed";
              serviceConfig = core.forwardHardening // {
                User = "microvm";
                Group = "kvm";
                ExecStart = core.forwardCommand pkgs cfg forward;
              };
            };
          }) cfg.expose
        ) instances
      )
      ++ lib.concatLists (
        lib.mapAttrsToList (
          name: cfg:
          map (forward: {
            "${hostForwardUnit name forward}@" = {
              description = "host forward for ${name} vsock port ${toString forward.vsockPort}";
              after = [ "microvm@${name}.service" ];
              requires = [ "microvm@${name}.service" ];
              unitConfig.CollectMode = "inactive-or-failed";
              serviceConfig = core.forwardHardening // {
                User = "microvm";
                Group = "kvm";
                ExecStart = core.hostForwardCommand pkgs cfg forward;
              };
            };
          }) (hostForwardsOf cfg)
        ) instances
      )
      ++ lib.mapAttrsToList (
        name: cfg:
        lib.mkIf (proxyOf cfg != null) {
          "${name}-egress-proxy" = {
            description = "domain-allowlist egress proxy for ${name}";
            wantedBy = [ "multi-user.target" ];
            serviceConfig = core.egressProxyServiceConfig pkgs (proxyOf cfg).port cfg.allowedDomains;
          };
        }
      ) instances
      ++ lib.concatLists (
        lib.mapAttrsToList (
          name: cfg:
          map (forward: {
            ${brokerUnit name forward} = {
              description = "credential broker for ${name} vsock port ${toString forward.vsockPort}";
              wantedBy = [ "multi-user.target" ];
              serviceConfig = core.brokerServiceConfig pkgs forward.broker forward.targetPort;
            };
          }) (brokeredOf cfg)
        ) instances
      )
    );

    systemd.sockets =
      forEachInstance (
        name: cfg:
        lib.listToAttrs (
          map (forward: {
            name = forwardUnit name forward;
            value = {
              description = "forward to ${name} guest port ${toString forward.guestPort}";
              wantedBy = [ "sockets.target" ];
              listenStreams = [ "${forward.listenAddress}:${toString forward.listenPort}" ];
              socketConfig = {
                Accept = true;
                MaxConnections = 64;
              };
            };
          }) cfg.expose
        )
      )
      // forEachInstance (
        name: cfg:
        lib.listToAttrs (
          map (forward: {
            name = hostForwardUnit name forward;
            value = {
              description = "host forward for ${name} vsock port ${toString forward.vsockPort}";
              wantedBy = [ "sockets.target" ];
              listenStreams = [ "vsock::${toString forward.vsockPort}" ];
              socketConfig = {
                Accept = true;
                MaxConnections = 64;
              };
            };
          }) (hostForwardsOf cfg)
        )
      );

    microvm.vms = lib.mapAttrs (name: cfg: {
      autostart = true;
      specialArgs = cfg.specialArgs // {
        agentSandbox = cfg // {
          inherit name;
          adminPublicKey = adminCfg.publicKey;
          kind = "microvm";
          # the guest-side proxy relays vsock to loopback, so a forwarded
          # service only ever needs to listen on loopback
          bindAddress = "127.0.0.1";
          hostForwards = hostForwardsOf cfg;
          proxy = proxyOf cfg;
          hasSecrets = cfg.secrets != { };
          tap = core.tapOf name;
          mac = core.macOf cfg;
          vsockCid = core.cidOf cfg;
        };
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

    networking.nftables.tables.fencr-nat = lib.mkIf (instances != { }) {
      family = "ip";
      content = ''
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          ${lib.concatStrings (lib.mapAttrsToList (_: cfg: core.natRuleFragment cfg) instances)}
        }
      '';
    };

    systemd.network = forEachInstance (
      name: cfg: {
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
        networks."11-${core.tapOf name}" = {
          matchConfig.Name = core.tapOf name;
          networkConfig.Bridge = cfg.bridge;
        };
      }
    );

    networking.firewall = {
      interfaces = forEachInstance (
        _: cfg: {
          ${cfg.bridge}.allowedTCPPorts = cfg.hostPorts;
        }
      );

      filterForward = true;
      # internet stays open; every private range is dropped, so a
      # compromised agent cannot walk the lan, a mesh, or a sibling
      # agent vm's subnet
      extraForwardRules = lib.concatStrings (
        lib.mapAttrsToList (_: cfg: core.forwardFilterFragment cfg) instances
      );
    };

    # the main firewall's interface rules only add ports, so globally
    # open ones (sshd at least) stay reachable from the bridges. this
    # chain runs before the main firewall and seals the vms' host access
    # to each bridge's declared allowedTCPPorts
    networking.nftables.tables.fencr-seal = lib.mkIf (instances != { }) {
      family = "inet";
      content = ''
        chain input {
          type filter hook input priority filter - 1; policy accept;
          ${lib.concatStrings (
            lib.mapAttrsToList (
              _: cfg:
              core.sealInputFragment cfg (
                lib.unique config.networking.firewall.interfaces.${cfg.bridge}.allowedTCPPorts
              )
            ) instances
          )}
        }
      '';
    };
  };
}
