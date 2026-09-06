self: pkgs:

# Calls the flakelet impl directly with a stub flakelet input and asserts the
# expected units exist. Building this check builds the guest system.
let
  inherit (pkgs) lib;
  core = import ../modules/core.nix { inherit lib; };
  module = self.flakelets.default {
    # only impl is exercised; option declarations stay unevaluated
    types = null;
  };
  result = module.impl {
    options = {
      id = 0;
      vcpu = 2;
      mem = 1024;
      dns = "9.9.9.9";
      allowedDomains = [
        "github.com"
        "*.github.com"
      ];
      authorizedKeys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerDummyOwnerDummyOwnerDummyOwnerDummyOwne check"
      ];
      secrets.raw = "/run/secrets/raw";
      allowedTCPDestinations = [ "192.168.1.50:8123" ];
      expose = [
        "33627"
        {
          listenAddress = "127.0.0.1";
          listenPort = 33628;
          guestPort = 22100;
        }
      ];
      hostForwards = [
        {
          vsockPort = 18764;
          targetPort = 8764;
          broker = {
            header = "Authorization";
            secretFile = "/run/secrets/broker-token";
          };
        }
      ];
      hostPorts = [ 443 ];
      guestModules = [ ];
    };
    inputs = {
      nixpkgs = {
        inherit pkgs lib;
      };
      flakelet = {
        name = "sbx";
        storePath = path: path;
      };
    };
  };
  resolve =
    name: options:
    core.resolveInstance {
      inherit name;
      options = {
        dns = "9.9.9.9";
      }
      // options;
    };
  resolved = resolve "sbx" {
    id = 0;
    allowedDomains = [ "github.com" ];
    allowedTCPDestinations = [ "192.168.1.50:8123" ];
    expose = [ "33627" ];
    hostPorts = [ 443 ];
  };
  longName = resolve "coding-agent-1" {
    id = 1;
    egress = "open";
  };
  # a forward's port names its units on both frontends, so a repeated port
  # would silently keep only the first entry
  sameListenPort = resolve "sbx" {
    id = 0;
    expose = [
      "127.0.0.1:22100:9119"
      "127.0.0.2:22100:9120"
    ];
  };
  sameGuestPort = resolve "sbx" {
    id = 0;
    expose = [
      "127.0.0.1:22100:9119"
      "127.0.0.1:22101:9119"
    ];
  };
  sameTargetPort = resolve "sbx" {
    id = 0;
    hostForwards = [
      {
        vsockPort = 18764;
        targetPort = 8764;
        broker = null;
      }
      {
        vsockPort = 18765;
        targetPort = 8764;
        broker = null;
      }
    ];
  };
  onProxyPort = resolve "sbx" {
    id = 0;
    allowedDomains = [ "github.com" ];
    hostForwards = [
      {
        vsockPort = 13128;
        targetPort = 8764;
        broker = null;
      }
    ];
  };
  expectedUnits = [
    "sbx"
    "sbx-setup"
    "fwd-33627@"
    "fwd-33628@"
    "hfwd-18764@"
    "hfwd-13128@"
    "broker-18764"
    "egress-proxy"
  ];
  expectedSockets = [
    "fwd-33627"
    "fwd-33628"
    "hfwd-13128"
    "hfwd-18764"
  ];
  actualUnits = builtins.attrNames result.services;
  actualSockets = builtins.attrNames result.sockets;
in
assert lib.assertMsg (
  actualUnits == lib.sort builtins.lessThan expectedUnits
) "flakelet check: units differ: ${toString actualUnits}";
assert lib.assertMsg (
  actualSockets == lib.sort builtins.lessThan expectedSockets
) "flakelet check: sockets differ: ${toString actualSockets}";
assert lib.assertMsg (resolved.cid == 3) "core check: wrong cid";
assert lib.assertMsg (resolved.ip == "10.30.1.2") "core check: wrong guest address";
assert lib.assertMsg (
  resolved.expose == [
    {
      listenAddress = "127.0.0.1";
      listenPort = 33627;
      guestPort = 33627;
    }
  ]
) "core check: expose was not resolved";
assert lib.assertMsg (resolved.proxy.port == 13128) "core check: proxy was not resolved";
assert lib.assertMsg (longName.errors != [ ]) "core check: long interface name accepted";
assert lib.assertMsg (
  sameListenPort.errors == [ "sbx: expose port 22100 declared twice" ]
) "core check: repeated expose port accepted";
assert lib.assertMsg (sameGuestPort.errors == [ ]) "core check: shared guest port rejected";
assert lib.assertMsg (
  sameTargetPort.errors == [ "sbx: hostForward target port 8764 declared twice" ]
) "core check: repeated hostForward target port accepted";
assert lib.assertMsg (
  onProxyPort.errors == [ "sbx: hostForward vsock port 13128 declared twice" ]
) "core check: hostForward on the egress proxy port accepted";
assert lib.assertMsg (lib.all (
  net: lib.hasInfix net (core.firewallOf longName).standalone
) core.specialUseNetworks.v4) "core check: open egress does not seal every special-use range";
assert lib.assertMsg (
  builtins.attrNames resolved.guest == [
    "bridge"
    "cid"
    "dns"
    "expose"
    "hostForwards"
    "hostIp"
    "ip"
    "mac"
    "mem"
    "name"
    "prefixLength"
    "proxy"
    "secretNames"
    "sshKeys"
    "tap"
    "uidBase"
    "vcpu"
  ]
) "core check: guest contract drifted";
assert lib.assertMsg (
  lib.length (
    core.fleetErrors {
      first = resolved;
      second = resolved;
    }
  ) == 2
) "core check: duplicate fleet resources accepted";
assert lib.assertMsg (
  result.services."fwd-33627@".after == [ "sbx.service" ]
) "unit check: vm dependency drifted";
assert lib.assertMsg result.services."fwd-33627@".serviceConfig.DynamicUser
  "unit check: flakelet forward identity drifted";
assert lib.assertMsg result.services.sbx.serviceConfig.DynamicUser
  "unit check: flakelet vm runs as root";
assert lib.assertMsg (
  result.services.sbx.serviceConfig.LoadCredential == [ "raw:/run/secrets/raw" ]
) "unit check: flakelet credential transport drifted";
assert lib.assertMsg (
  result.services.sbx.serviceConfig.MemoryMax == core.defaults.memoryMax
  && result.services.sbx.serviceConfig.CPUQuota == core.defaults.cpuQuota
) "unit check: flakelet vm has no resource cap";
assert lib.assertMsg (
  result.services.sbx.serviceConfig.CapabilityBoundingSet == "CAP_SETUID CAP_SETGID"
  && result.services.sbx.serviceConfig.DevicePolicy == "closed"
  &&
    result.services.sbx.serviceConfig.RestrictAddressFamilies == [
      "AF_UNIX"
      "AF_INET"
    ]
  && result.services.sbx.requires == [ "sbx-setup.service" ]
) "unit check: flakelet vm confinement drifted";
assert lib.assertMsg (resolved.uidBase == 1000000) "core check: wrong uid base";
assert lib.assertMsg (
  let
    seal = (core.firewallOf resolved).standalone;
    occurrences = needle: lib.length (lib.splitString needle seal) - 1;
  in
  occurrences "priority filter - 1;" == 2
  && occurrences ''iifname "br-sbx" meta nfproto ipv6 drop'' == 2
) "core check: seal chain priority or v6 drop drifted";
assert lib.assertMsg (
  result.sockets."fwd-33627".socketConfig.ListenStream == "127.0.0.1:33627"
) "unit check: listen endpoint drifted";
assert lib.assertMsg (
  result.sockets."hfwd-18764".socketConfig.TriggerLimitIntervalSec == 0
) "unit check: vsock trigger limit is enabled";
assert lib.assertMsg (
  result.services."broker-18764".serviceConfig.RuntimeDirectory == "fencr-broker-sbx-18764"
  && result.services."broker-18764".serviceConfig.Group == "kvm"
  &&
    lib.hasSuffix "unix:/run/fencr-broker-sbx-18764/broker.sock"
      result.services."hfwd-18764@".serviceConfig.ExecStart
) "unit check: broker is not on its unix socket";
pkgs.writeText "fencr-flakelet-check" (builtins.toJSON result)
