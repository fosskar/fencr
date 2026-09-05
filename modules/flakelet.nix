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
      description = "host files passed through qemu fw_cfg and materialized in volatile guest /run/agent-secrets; guest root can read them.";
    };
    egress = {
      type = types.enum "egress" [
        "open"
        "closed"
      ];
      default = "closed";
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

      resolved = core.resolveInstance {
        inherit name options;
        sshKeys = options.authorizedKeys;
      };
      instance =
        if resolved.errors == [ ] then
          resolved
        else
          throw "fencr: ${lib.concatStringsSep "; " resolved.errors}";
      credentialFiles = lib.genAttrs (lib.attrNames options.secrets) (
        secretName: "/run/credentials/${name}.service/${secretName}"
      );
      units = core.hostUnits hostPkgs instance {
        vmUnit = "${name}.service";
        identity.DynamicUser = true;
        forwardName = forward: "fwd-${toString forward.listenPort}";
        hostForwardName = forward: "hfwd-${toString forward.vsockPort}";
        proxyName = "egress-proxy";
        brokerName = forward: "broker-${toString forward.vsockPort}";
      };
      ruleset = hostPkgs.writeText "fencr-${name}.nft" (core.firewallOf instance).standalone;

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
        specialArgs.agentSandbox = instance.guest // {
          inherit credentialFiles;
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
            DynamicUser = true;
            SupplementaryGroups = [ "kvm" ];
            StateDirectory = [
              "fencr-run-${name}"
              "fencr-vms/${name}"
            ];
            WorkingDirectory = "/var/lib/fencr-run-${name}";
            LoadCredential = lib.mapAttrsToList (secretName: source: "${secretName}:${source}") options.secrets;
            CapabilityBoundingSet = "";
            DevicePolicy = "closed";
            DeviceAllow = [
              "/dev/kvm rw"
              "/dev/net/tun rw"
              "/dev/vhost-vsock rw"
            ];
            LockPersonality = true;
            NoNewPrivileges = true;
            PrivateTmp = true;
            ProtectClock = true;
            ProtectControlGroups = true;
            ProtectHome = true;
            ProtectHostname = true;
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectKernelTunables = true;
            ProtectSystem = "strict";
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            SystemCallArchitectures = "native";
            UMask = "0077";
            Restart = "on-failure";
            RestartSec = 5;
          };
        };
      }
      // units.services;

      inherit (units) sockets;
    };
}
