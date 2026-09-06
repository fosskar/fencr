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
      default = core.defaults.secrets;
      description = "host files passed through fw_cfg and materialized in volatile guest /run/agent-secrets; guest root can read them.";
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
      default = core.defaults.allowedDomains;
      description = "domains reachable through the egress proxy (fnmatch patterns); requires egress = closed.";
    };
    allowedTCPDestinations = {
      type = types.listOf destinationType;
      default = core.defaults.allowedTCPDestinations;
      description = "private IPv4 TCP destinations reachable from the vm, as address:port strings or attrsets.";
    };
    expose = {
      type = types.listOf exposeType;
      default = core.defaults.expose;
      description = "guest loopback ports exposed on host endpoints over vsock; every host account can also reach the guest port directly through the vm's cid.";
    };
    hostForwards = {
      type = types.listOf hostForwardType;
      default = core.defaults.hostForwards;
      description = "guest loopback ports forwarded to host ports over vsock.";
    };
    hostPorts = {
      type = types.listOf types.int;
      default = core.defaults.hostPorts;
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
      # destroy is a no-op on an absent table, so one nft -f replaces the seal
      ruleset = hostPkgs.writeText "fencr-${name}.nft" ''
        destroy table inet fencr-${name}
        destroy table ip fencr-${name}-nat
        ${(core.firewallOf instance).standalone}
      '';
      # crosvm jails every device in a user namespace, and marks all guest
      # memory mergeable: the host must allow the former and not run ksm
      setupScript = hostPkgs.writeShellScript "fencr-${name}-setup" ''
        set -eu
        test "$(${hostPkgs.procps}/bin/sysctl -n user.max_user_namespaces)" -gt 0
        if [ -e /sys/kernel/mm/ksm/run ]; then echo 0 > /sys/kernel/mm/ksm/run; fi
        ${hostPkgs.procps}/bin/sysctl -q net.ipv4.conf.all.forwarding=1
        ip=${hostPkgs.iproute2}/bin/ip
        $ip link show ${instance.bridge} >/dev/null 2>&1 || $ip link add ${instance.bridge} type bridge
        $ip addr replace ${instance.hostIp}/${toString instance.prefixLength} dev ${instance.bridge}
        $ip link set ${instance.bridge} up
        $ip link set ${instance.tap} master ${instance.bridge}
        $ip link set ${instance.tap} up
        ${hostPkgs.nftables}/bin/nft -f ${ruleset}
      '';

      teardownScript = hostPkgs.writeShellScript "fencr-${name}-teardown" ''
        ${hostPkgs.nftables}/bin/nft destroy table inet fencr-${name}
        ${hostPkgs.nftables}/bin/nft destroy table ip fencr-${name}-nat
        ${hostPkgs.iproute2}/bin/ip link del ${instance.tap} 2>/dev/null || true
        ${hostPkgs.iproute2}/bin/ip link del ${instance.bridge} 2>/dev/null || true
        exit 0
      '';

      guestSystem = flakeInputs.nixpkgs.lib.nixosSystem {
        system = hostPkgs.stdenv.hostPlatform.system;
        specialArgs.agentSandbox = units.guest;
        modules = [
          flakeInputs.microvm.nixosModules.microvm
          (core.guestBase flakeInputs.microvm)
        ]
        ++ map (path: import (storePath path)) options.guestModules;
      };
      runner = guestSystem.config.microvm.declaredRunner;
    in
    {
      services = {
        "${name}-setup" = core.setupService hostPkgs instance;
        ${name} = lib.recursiveUpdate (core.vmService instance runner) {
          serviceConfig = {
            ExecStartPre = "+${setupScript}";
            ExecStopPost = "+${teardownScript}";
          };
        };
      }
      // units.services;

      inherit (units) sockets;
    };
}
