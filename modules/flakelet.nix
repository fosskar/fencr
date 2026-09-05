# the flakelet surface: the same sealed vm, expressed as systemd units so a
# host can update the sandbox independently of its own generation. host-level
# plumbing the nixos module declares (bridge, nftables, kernel module) becomes
# unit payloads here; the guest system evaluates against fencr's own pinned
# inputs, not the host's nixpkgs. docs/decisions/flakelet-module.md.
{ inputs }:
let
  flakeInputs = inputs;
in
{ types, ... }:
let
  destinationType = types.union [
    types.string
    (types.struct "destination" {
      address = types.string;
      port = types.int;
    })
  ];
  exposeType = types.union [
    types.string
    (types.struct "expose" {
      listenAddress = types.string;
      listenPort = types.int;
      guestPort = types.int;
    })
  ];
  brokerType = types.struct "broker" {
    port = types.int;
    header = types.string;
    secretFile = types.string;
  };
  hostForwardType = types.struct "hostForward" {
    vsockPort = types.int;
    targetPort = types.int;
    broker = types.option brokerType;
  };
in
{
  options = {
    id = {
      type = types.int;
      description = "unique instance index; derives bridge, subnet, tap, mac and vsock cid.";
    };
    vcpu = {
      type = types.int;
      default = 4;
    };
    mem = {
      type = types.int;
      default = 4096;
      description = "guest memory ceiling.";
    };
    dns = {
      type = types.string;
      description = "resolver the vm may reach; also handed to the guest.";
    };
    authorizedKeys = {
      type = types.listOf types.string;
      default = [ ];
      description = "public keys authorized as root in the vm; the flakelet host passes admin and owner keys as one list.";
    };
    secrets = {
      type = types.attrsOf types.string;
      default = { };
      description = "host files staged read-only into the vm under /run/agent-secrets.";
    };
    egress = {
      type = types.enum "egress" [
        "open"
        "closed"
      ];
      defaultFunc = { options, ... }: if options.allowedDomains == [ ] then "open" else "closed";
      description = "open: internet and dns reachable, private ranges sealed. closed: only allowedTCPDestinations. defaults to closed when allowedDomains is set.";
    };
    allowedDomains = {
      type = types.listOf types.string;
      default = [ ];
      description = "domains reachable through the egress proxy (fnmatch patterns); requires egress = closed.";
    };
    allowedTCPDestinations = {
      type = types.listOf destinationType;
      default = [ ];
      description = "private IPv4 TCP destinations reachable from the vm, as address:port strings or attrsets.";
    };
    expose = {
      type = types.listOf exposeType;
      default = [ ];
      description = "guest loopback ports exposed on host endpoints over vsock.";
    };
    hostForwards = {
      type = types.listOf hostForwardType;
      default = [ ];
      description = "guest loopback ports forwarded to host ports over vsock.";
    };
    hostPorts = {
      type = types.listOf types.int;
      default = [ ];
      description = "host TCP ports reachable from the vm over the bridge.";
    };
    guestModules = {
      type = types.listOf types.string;
      default = [ ];
      description = "store paths of nixos modules to run inside the vm.";
    };
  };

  impl =
    { options, inputs }:
    let
      hostPkgs = inputs.nixpkgs.pkgs;
      lib = inputs.nixpkgs.lib;
      name = inputs.flakelet.name;
      storePath = inputs.flakelet.storePath;
      core = import ./core.nix { inherit lib; };

      proxy =
        if options.allowedDomains == [ ] then
          null
        else if core.domainPatternErrors options.allowedDomains != [ ] then
          throw "fencr: invalid allowedDomains: ${lib.concatStringsSep "; " (core.domainPatternErrors options.allowedDomains)}"
        else if options.egress != "closed" then
          throw "fencr: allowedDomains requires egress = \"closed\"; with open egress the proxy filter is decoration"
        else
          { port = core.proxyPortOf options; };

      hostForwards =
        options.hostForwards
        ++ lib.optional (proxy != null) {
          vsockPort = proxy.port;
          targetPort = proxy.port;
          broker = null;
        };

      cfg = {
        inherit (options)
          id
          vcpu
          mem
          dns
          egress
          ;
        inherit hostForwards;
        allowedTCPDestinations = map core.parseDestination options.allowedTCPDestinations;
        expose = map core.parseExpose options.expose;
        bridge = core.bridgeOf name;
        ip = core.ipOf options;
        hostIp = core.hostIpOf options;
        prefixLength = 24;
      };

      brokered = lib.filter (forward: forward.broker != null) options.hostForwards;

      # standalone nftables tables: the nixos module hooks the host firewall,
      # here the same fragments get their own chains. the trailing drop on
      # oifname replaces the host firewall's default-deny for unsolicited
      # inbound forwards.
      ruleset = hostPkgs.writeText "fencr-${name}.nft" ''
        table ip fencr-${name}-nat {
          chain postrouting {
            type nat hook postrouting priority srcnat; policy accept;
            ${core.natRuleFragment cfg}
          }
        }
        table inet fencr-${name} {
          chain forward {
            type filter hook forward priority filter; policy accept;
            ${core.forwardFilterFragment cfg}
            oifname "${cfg.bridge}" drop
          }
          chain input {
            type filter hook input priority -1; policy accept;
            ${core.sealInputFragment cfg options.hostPorts}
          }
        }
      '';

      setupScript = hostPkgs.writeShellScript "fencr-${name}-setup" ''
        set -eu
        ${hostPkgs.kmod}/bin/modprobe vhost_vsock
        ${hostPkgs.procps}/bin/sysctl -q net.ipv4.conf.all.forwarding=1
        ip=${hostPkgs.iproute2}/bin/ip
        $ip link show ${cfg.bridge} >/dev/null 2>&1 || $ip link add ${cfg.bridge} type bridge
        $ip addr replace ${cfg.hostIp}/${toString cfg.prefixLength} dev ${cfg.bridge}
        $ip link set ${cfg.bridge} up
        $ip link show ${core.tapOf name} >/dev/null 2>&1 || $ip tuntap add ${core.tapOf name} mode tap
        $ip link set ${core.tapOf name} master ${cfg.bridge}
        $ip link set ${core.tapOf name} up
        ${hostPkgs.nftables}/bin/nft delete table inet fencr-${name} 2>/dev/null || true
        ${hostPkgs.nftables}/bin/nft delete table ip fencr-${name}-nat 2>/dev/null || true
        ${hostPkgs.nftables}/bin/nft -f ${ruleset}
        install -d -m 0755 ${core.stateDirOf name}
        ${lib.optionalString (options.secrets != { }) ''
          install -d -m 0700 /var/lib/fencr/${name}
          install -d -m 0755 ${core.secretsDirOf name}
          ${lib.concatStringsSep "\n" (
            lib.mapAttrsToList (
              secretName: src: "install -m 0400 ${src} ${core.secretsDirOf name}/${secretName}"
            ) options.secrets
          )}
        ''}
      '';

      teardownScript = hostPkgs.writeShellScript "fencr-${name}-teardown" ''
        ${hostPkgs.nftables}/bin/nft delete table inet fencr-${name} 2>/dev/null || true
        ${hostPkgs.nftables}/bin/nft delete table ip fencr-${name}-nat 2>/dev/null || true
        ${hostPkgs.iproute2}/bin/ip link del ${core.tapOf name} 2>/dev/null || true
        ${hostPkgs.iproute2}/bin/ip link del ${cfg.bridge} 2>/dev/null || true
        exit 0
      '';

      guestSystem = flakeInputs.nixpkgs.lib.nixosSystem {
        system = hostPkgs.stdenv.hostPlatform.system;
        specialArgs.agentSandbox = cfg // {
          inherit name;
          sshKeys = options.authorizedKeys;
          kind = "microvm";
          bindAddress = "127.0.0.1";
          inherit proxy;
          hasSecrets = options.secrets != { };
          tap = core.tapOf name;
          mac = core.macOf options;
          vsockCid = core.cidOf options;
        };
        modules = [
          flakeInputs.microvm.nixosModules.microvm
          core.guestBase
        ]
        ++ map (path: import (storePath path)) options.guestModules;
      };
      runner = guestSystem.config.microvm.declaredRunner;
    in
    {
      services = {
        ${name} = {
          description = "fencr sandbox ${name}";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            ExecStartPre = "+${setupScript}";
            ExecStart = "${runner}/bin/microvm-run";
            ExecStop = "${runner}/bin/microvm-shutdown";
            ExecStopPost = "+${teardownScript}";
            StateDirectory = "fencr-run-${name}";
            WorkingDirectory = "/var/lib/fencr-run-${name}";
            Restart = "on-failure";
            RestartSec = 5;
          };
        };
      }
      // lib.listToAttrs (
        map (forward: {
          name = "fwd-${toString forward.listenPort}@";
          value = {
            description = "forward to ${name} guest port ${toString forward.guestPort}";
            after = [ "${name}.service" ];
            requires = [ "${name}.service" ];
            unitConfig.CollectMode = "inactive-or-failed";
            serviceConfig = core.forwardHardening // {
              DynamicUser = true;
              ExecStart = core.forwardCommand hostPkgs cfg forward;
            };
          };
        }) cfg.expose
      )
      // lib.listToAttrs (
        map (forward: {
          name = "hfwd-${toString forward.vsockPort}@";
          value = {
            description = "host forward for ${name} vsock port ${toString forward.vsockPort}";
            after = [ "${name}.service" ];
            requires = [ "${name}.service" ];
            unitConfig.CollectMode = "inactive-or-failed";
            serviceConfig = core.forwardHardening // {
              DynamicUser = true;
              ExecStart = core.hostForwardCommand hostPkgs cfg forward;
            };
          };
        }) hostForwards
      )
      // lib.optionalAttrs (proxy != null) {
        egress-proxy = {
          description = "domain-allowlist egress proxy for ${name}";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = core.egressProxyServiceConfig hostPkgs proxy.port options.allowedDomains;
        };
      }
      // lib.listToAttrs (
        map (forward: {
          name = "broker-${toString forward.vsockPort}";
          value = {
            description = "credential broker for ${name} vsock port ${toString forward.vsockPort}";
            wantedBy = [ "multi-user.target" ];
            serviceConfig = core.brokerServiceConfig hostPkgs forward.broker forward.targetPort;
          };
        }) brokered
      );

      sockets =
        lib.listToAttrs (
          map (forward: {
            name = "fwd-${toString forward.listenPort}";
            value = {
              description = "forward to ${name} guest port ${toString forward.guestPort}";
              wantedBy = [ "sockets.target" ];
              socketConfig = {
                ListenStream = "${forward.listenAddress}:${toString forward.listenPort}";
                Accept = true;
                MaxConnections = 64;
              };
            };
          }) cfg.expose
        )
        // lib.listToAttrs (
          map (forward: {
            name = "hfwd-${toString forward.vsockPort}";
            value = {
              description = "host forward for ${name} vsock port ${toString forward.vsockPort}";
              wantedBy = [ "sockets.target" ];
              socketConfig = {
                ListenStream = "vsock::${toString forward.vsockPort}";
                Accept = true;
                MaxConnections = 64;
              };
            };
          }) hostForwards
        );
    };
}
