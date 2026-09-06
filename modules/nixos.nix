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
      credentials = config.fencr.credentials;
    }
  ) instances;
  unitSets = lib.mapAttrs (_: core.hostUnits pkgs) resolvedInstances;
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
  # the guest evaluates against the host's nixpkgs
  guestSystems = lib.mapAttrs (
    name: cfg:
    import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit pkgs;
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = cfg.specialArgs // {
        agentSandbox = unitSets.${name}.guest;
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
  options.fencr.guestSystems = lib.mkOption {
    type = lib.types.attrsOf lib.types.raw;
    readOnly = true;
    description = "the evaluated guest system of every vm, keyed by vm name.";
  };

  options.fencr.credentials = lib.mkOption {
    default = { };
    description = "credentials a vm may use without ever seeing the value, granted by name in fencr.vms.<name>.credentials.";
    type = lib.types.attrsOf (
      lib.types.submodule {
        options = {
          upstream = lib.mkOption {
            type = lib.types.str;
            example = "https://api.anthropic.com";
            description = ''
              where requests go, with the credential injected: a public
              https api or a plain http port on host loopback. private
              ranges are refused.
            '';
          };
          domain = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "mcp.fencr";
            description = ''
              the name a vm calls. it resolves to the host, where the
              credential's proxy answers with a certificate from the
              host's own authority, which the vm trusts. defaults to the
              upstream's host; an upstream on host loopback needs one.
            '';
          };
          header = lib.mkOption {
            type = lib.types.str;
            default = "Authorization";
            description = "request header that carries the credential.";
          };
          secretFile = lib.mkOption {
            type = lib.types.path;
            description = "host file with the raw header value, for example \"Bearer x\"; never enters a vm.";
          };
        };
      }
    );
  };

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
          stateSize = lib.mkOption {
            type = lib.types.int;
            default = core.defaults.stateSize;
            description = ''
              size in MiB of the vm's /var/lib, a sparse disk image at
              /var/lib/fencr-vms/<name>/state.img. a larger value grows the
              image and its filesystem on the next start; it never shrinks.
            '';
          };
          cpuQuota = lib.mkOption {
            type = lib.types.str;
            default = core.defaults.cpuQuota;
          };
          secrets = lib.mkOption {
            type = lib.types.attrsOf lib.types.path;
            default = core.defaults.secrets;
            description = ''
              host files the guest fetches over vsock at boot into its
              volatile /run/agent-secrets, mode 0400. guest root can read
              these raw values. for a key a program must hold itself, a
              signing key or a recovery key; an http api key is a
              credential instead, which the vm can use but never read.
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
            default = core.defaults.allowedDomains;
            example = lib.literalExpression ''[ "github.com" "*.github.com" ]'';
            description = ''
              domains reachable over tls; "*.github.com" does not match the
              bare "github.com", list both. implies egress = "closed": the
              vm resolves every name to the host, which reads the server
              name from the tls handshake and passes allowed connections
              through unread. no proxy variables, no interception, and no
              dns leaves the host.
            '';
          };

          allowedTCPDestinations = lib.mkOption {
            type = lib.types.listOf destinationType;
            default = core.defaults.allowedTCPDestinations;
            description = ''
              IPv4 TCP destinations reachable from the vm, as
              "<address>:<port>" or { address; port; }. each entry is an
              explicit exception to the default closed egress policy.
            '';
          };

          expose = lib.mkOption {
            type = lib.types.listOf exposeType;
            default = core.defaults.expose;
            example = lib.literalExpression ''[ "33627" ]'';
            description = ''
              guest loopback ports exposed on host endpoints over vsock.
              listenAddress narrows tcp clients only: members of group kvm
              can also reach the guest port directly through the vm's
              vsock socket.
            '';
          };

          hostForwards = lib.mkOption {
            type = lib.types.listOf (
              lib.types.submodule {
                options = {
                  vsockPort = lib.mkOption { type = lib.types.port; };
                  targetPort = lib.mkOption { type = lib.types.port; };
                };
              }
            );
            default = core.defaults.hostForwards;
            description = "guest loopback ports forwarded to host ports over vsock.";
          };

          credentials = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = core.defaults.credentials;
            example = lib.literalExpression ''[ "anthropic" ]'';
            description = ''
              names from fencr.credentials this vm may use. the vm calls
              the credential's domain as it would anywhere; the name
              resolves to the host, whose proxy ends the tls with a
              certificate the vm trusts, injects the credential and sends
              the request on. the value never enters the vm.
            '';
          };

          hostPorts = lib.mkOption {
            type = lib.types.listOf lib.types.port;
            default = core.defaults.hostPorts;
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
    fencr.guestSystems = guestSystems;

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

    # `ssh <vm-name>` reaches the guest's vsock sshd through the vm's ssh
    # socket, which every host account may open, so any host user holding
    # an authorized key gets in with their own identity. no bridge ip, no
    # network listener anywhere
    programs.ssh.extraConfig = lib.concatStrings (
      lib.mapAttrsToList (
        name: cfg:
        lib.optionalString (cfg.guest.sshKeys != [ ]) ''
          Host ${name}
            User root
            ProxyCommand ${pkgs.socat}/bin/socat - UNIX-CONNECT:${core.sshSocketOf name}
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
    # the runtime directory holds the vm's vsock sockets and admits the
    # relays, group kvm, and nobody else
    systemd.tmpfiles.rules = [
      "d /var/lib/fencr-vms 0710 root kvm -"
    ]
    ++ map (name: "d ${core.stateDirOf name} 0700 ${core.userOf name} kvm -") (lib.attrNames instances)
    ++ map (name: "d ${core.runDirOf name} 0750 ${core.userOf name} kvm -") (lib.attrNames instances);

    systemd.services = lib.mkMerge (
      lib.mapAttrsToList (name: instance: {
        "fencr-${name}" = core.vmService pkgs instance guestSystems.${name}.config.microvm.declaredRunner;
      }) resolvedInstances
      ++ map (units: units.services) (lib.attrValues unitSets)
      ++
        lib.optional (lib.any (instance: instance.credentials != [ ]) (lib.attrValues resolvedInstances))
          {
            fencr-ca = core.caService pkgs config.networking.hostName;
          }
    );

    systemd.sockets = lib.mkMerge (map (units: units.sockets) (lib.attrValues unitSets));

    # masquerade by the vm's source address instead of networking.nat, so
    # the module needs no knowledge of the host's uplink interface
    boot.kernel.sysctl."net.ipv4.conf.all.forwarding" = lib.mkDefault true;

    # same-page merging lets a guest probe memory across vms
    hardware.ksm.enable = false;

    # the seal tables stand beside the main firewall rather than inside it, so
    # nothing nixpkgs puts ahead of extraForwardRules (icmpv6, dnat) runs
    # before the seal, and the host keeps its own forward policy. the main
    # firewall's interface rules only add ports, so globally open ones (sshd
    # at least) would stay reachable from the bridges; the seal's input chain
    # runs first and admits only the bridge's declared allowedTCPPorts
    networking.nftables.tables = forEachInstance (
      _: cfg:
      core.firewallOf (
        cfg
        // {
          hostPorts = lib.unique config.networking.firewall.interfaces.${cfg.bridge}.allowedTCPPorts;
        }
      )
    );

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

    # the seal's input chain accepts first, but the main chain's drop policy
    # still runs after it, so the egress proxy's ports open there too
    networking.firewall.interfaces = forEachInstance (
      _: cfg: {
        ${cfg.bridge} = {
          allowedTCPPorts = cfg.hostPorts ++ lib.optional cfg.proxy 443;
          allowedUDPPorts = lib.optional cfg.dnsProxy 53;
        };
      }
    );

    # with filterForward the main forward chain drops by policy, and a drop
    # in any chain is final even after the seal accepted
    networking.firewall.extraForwardRules = lib.concatMapStrings (cfg: ''
      iifname "${cfg.bridge}" accept
    '') (lib.attrValues resolvedInstances);
  };
}
