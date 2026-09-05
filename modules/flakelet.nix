# the flakelet surface: the same sealed vm, expressed as systemd units so a
# host can update the sandbox independently of its own generation. host-level
# plumbing the nixos module declares (bridge, nftables, kernel module) becomes
# unit payloads here; the guest system evaluates against fencr's own pinned
# inputs, not the host's nixpkgs. docs/decisions/flakelet-module.md.
{ inputs }:
let
  flakeInputs = inputs;
  core = import ./core.nix { lib = flakeInputs.nixpkgs.lib; };
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
      default = core.defaults.vcpu;
    };
    mem = {
      type = types.int;
      default = core.defaults.mem;
      description = "guest memory ceiling; free page reporting returns unused memory to the host.";
    };
    memoryMax = {
      type = types.string;
      default = core.defaults.memoryMax;
      description = "hard cap on the whole vm unit, enforced by the host; guest ceiling plus hypervisor overhead.";
    };
    cpuQuota = {
      type = types.string;
      default = core.defaults.cpuQuota;
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
      description = "host files passed through qemu fw_cfg and materialized in volatile guest /run/agent-secrets; guest root can read them.";
    };
    egress = {
      type = types.enum "egress" [
        "open"
        "closed"
      ];
      default = core.defaults.egress;
      description = "open: internet and dns reachable, private ranges sealed. closed: only allowedTCPDestinations; this is the default.";
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
      description = "guest loopback ports exposed on host endpoints over vsock; every host account can also reach the guest port directly through the vm's cid.";
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

      resolved = core.resolveInstance {
        inherit name options;
        sshKeys = options.authorizedKeys;
      };
      instance =
        if resolved.errors == [ ] then
          resolved
        else
          throw "fencr: ${lib.concatStringsSep "; " resolved.errors}";
      units = core.hostUnits hostPkgs instance {
        vmUnit = "${name}.service";
        forwardName = forward: "fwd-${toString forward.listenPort}";
        hostForwardName = forward: "hfwd-${toString forward.vsockPort}";
        proxyName = "egress-proxy";
        brokerName = forward: "broker-${toString forward.vsockPort}";
      };
      ruleset = hostPkgs.writeText "fencr-${name}.nft" (core.firewallOf instance).standalone;
      # the runner's working directory: qmp and virtiofs sockets, shared by
      # the virtiofsd unit (root) and the vm unit (dynamic user in kvm)
      runDir = "/run/fencr-${name}";

      setupScript = hostPkgs.writeShellScript "fencr-${name}-setup" ''
        set -eu
        ${hostPkgs.kmod}/bin/modprobe vhost_vsock
        ${hostPkgs.procps}/bin/sysctl -q net.ipv4.conf.all.forwarding=1
        ip=${hostPkgs.iproute2}/bin/ip
        $ip link show ${instance.bridge} >/dev/null 2>&1 || $ip link add ${instance.bridge} type bridge
        $ip addr replace ${instance.hostIp}/${toString instance.prefixLength} dev ${instance.bridge}
        $ip link set ${instance.bridge} up
        $ip link show ${instance.tap} >/dev/null 2>&1 || $ip tuntap add ${instance.tap} mode tap group kvm ${
          lib.optionalString (options.vcpu > 1) "multi_queue"
        }
        $ip link set ${instance.tap} master ${instance.bridge}
        $ip link set ${instance.tap} up
        ${hostPkgs.nftables}/bin/nft delete table inet fencr-${name} 2>/dev/null || true
        ${hostPkgs.nftables}/bin/nft delete table ip fencr-${name}-nat 2>/dev/null || true
        ${hostPkgs.nftables}/bin/nft -f ${ruleset}
      '';

      teardownScript = hostPkgs.writeShellScript "fencr-${name}-teardown" ''
        ${hostPkgs.nftables}/bin/nft delete table inet fencr-${name} 2>/dev/null || true
        ${hostPkgs.nftables}/bin/nft delete table ip fencr-${name}-nat 2>/dev/null || true
        ${hostPkgs.iproute2}/bin/ip link del ${instance.tap} 2>/dev/null || true
        ${hostPkgs.iproute2}/bin/ip link del ${instance.bridge} 2>/dev/null || true
        exit 0
      '';

      guestSystem = flakeInputs.nixpkgs.lib.nixosSystem {
        system = hostPkgs.stdenv.hostPlatform.system;
        specialArgs.agentSandbox = units.guest;
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
        # the virtiofs daemons the runner dials for its store and state
        # shares; microvm.nix's host module runs the same script as root
        "${name}-virtiofsd" = {
          description = "virtiofs daemons for fencr sandbox ${name}";
          before = [ "${name}.service" ];
          partOf = [ "${name}.service" ];
          serviceConfig = {
            ExecStart = "${runner}/bin/virtiofsd-run";
            Type = "notify";
            NotifyAccess = "all";
            KillMode = "mixed";
            Group = "kvm";
            RuntimeDirectory = "fencr-${name}";
            RuntimeDirectoryMode = "0770";
            WorkingDirectory = runDir;
            # virtiofsd exports this tree and starts before the vm unit, so it
            # owns creating it; the vm's ExecStartPre would be too late and
            # the state share would fail to connect on a first boot
            StateDirectory = "fencr-vms/${name}";
            StateDirectoryMode = "0700";
            LimitNOFILE = 1048576;
            PrivateTmp = true;
            Restart = "always";
            RestartSec = 5;
          };
        };
        ${name} = {
          description = "fencr sandbox ${name}";
          wantedBy = [ "multi-user.target" ];
          after = [
            "network.target"
            "${name}-virtiofsd.service"
          ];
          requires = [ "${name}-virtiofsd.service" ];
          serviceConfig =
            core.vmServiceConfig {
              inherit instance;
              writablePaths = [ runDir ];
            }
            // {
              ExecStartPre = "+${setupScript}";
              ExecStart = "${runner}/bin/microvm-run";
              ExecStop = "${runner}/bin/microvm-shutdown";
              ExecStopPost = "+${teardownScript}";
              DynamicUser = true;
              SupplementaryGroups = [ "kvm" ];
              WorkingDirectory = runDir;
              Restart = "on-failure";
              RestartSec = 5;
            };
        };
      }
      // units.services;

      inherit (units) sockets;
    };
}
