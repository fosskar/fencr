_self: pkgs:

# Probes the builders in modules/core.nix without a host: instance derivation,
# the seal text and the host units. Nothing is built.
let
  inherit (pkgs) lib;
  core = import ../modules/core.nix { inherit lib; };
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
  };
  units = core.hostUnits pkgs resolved;
  longName = resolve "coding-agent-1" {
    id = 1;
    egress = "open";
  };
  # a forward's port names its units, so a repeated port would silently keep
  # only the first entry
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
  seal = lib.concatStrings (lib.mapAttrsToList (_: table: table.content) (core.firewallOf resolved));
  occurrences = needle: lib.length (lib.splitString needle seal) - 1;
in
assert lib.assertMsg (resolved.cid == 3) "core check: wrong cid";
assert lib.assertMsg (resolved.ip == "10.30.1.2") "core check: wrong guest address";
assert lib.assertMsg (resolved.uidBase == 1000000) "core check: wrong uid base";
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
assert lib.assertMsg (
  lib.length (
    core.fleetErrors {
      first = resolved;
      second = resolved;
    }
  ) == 2
) "core check: duplicate fleet resources accepted";
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
assert lib.assertMsg (lib.all (
  net:
  lib.hasInfix net (
    lib.concatStrings (lib.mapAttrsToList (_: table: table.content) (core.firewallOf longName))
  )
) core.specialUseNetworks.v4) "core check: open egress does not seal every special-use range";
assert lib.assertMsg (
  occurrences "priority filter - 1;" == 2
  && occurrences ''iifname "br-sbx" meta nfproto ipv6 drop'' == 2
) "core check: seal chain priority or v6 drop drifted";
assert lib.assertMsg (
  builtins.attrNames units.sockets == [
    "sbx-forward-33627"
    "sbx-host-forward-13128"
    "sbx-host-forward-18764"
  ]
  && units.sockets."sbx-forward-33627".socketConfig.ListenStream == "127.0.0.1:33627"
  && units.sockets."sbx-host-forward-18764".socketConfig.TriggerLimitIntervalSec == 0
) "unit check: host sockets drifted";
assert lib.assertMsg (
  units.services."sbx-forward-33627@".after == [ "fencr-sbx.service" ]
  && units.services."sbx-forward-33627@".serviceConfig.DynamicUser
) "unit check: forward relay drifted";
assert lib.assertMsg (
  units.services."sbx-broker-18764".serviceConfig.RuntimeDirectory == "fencr-broker-sbx-18764"
  && units.services."sbx-broker-18764".serviceConfig.Group == "kvm"
  &&
    lib.hasSuffix "unix:/run/fencr-broker-sbx-18764/broker.sock"
      units.services."sbx-host-forward-18764@".serviceConfig.ExecStart
) "unit check: broker is not on its unix socket";
pkgs.writeText "fencr-core-check" (builtins.toJSON units.unitNames)
