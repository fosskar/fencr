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
      credentials.api = {
        upstream = "https://api.example.com";
        header = "Authorization";
        secretFile = "/run/secrets/api-token";
      };
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
      }
    ];
    credentials = [ "api" ];
    hostPorts = [ 443 ];
  };
  unknownCredential = resolve "sbx" {
    id = 0;
    credentials = [ "nope" ];
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
      }
      {
        vsockPort = 18765;
        targetPort = 8764;
      }
    ];
  };
  seal = lib.concatStrings (lib.mapAttrsToList (_: table: table.content) (core.firewallOf resolved));
  occurrences = needle: lib.length (lib.splitString needle seal) - 1;
in
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
assert lib.assertMsg (
  resolved.proxy
  && resolved.guest.dns == "10.30.1.1"
  && !longName.proxy
  && longName.guest.dns == "9.9.9.9"
) "core check: the egress proxy is not the guest's resolver";
assert lib.assertMsg (longName.errors != [ ]) "core check: long interface name accepted";
assert lib.assertMsg (
  sameListenPort.errors == [ "sbx: expose port 22100 declared twice" ]
) "core check: repeated expose port accepted";
assert lib.assertMsg (sameGuestPort.errors == [ ]) "core check: shared guest port rejected";
assert lib.assertMsg (
  sameTargetPort.errors == [ "sbx: hostForward target port 8764 declared twice" ]
) "core check: repeated hostForward target port accepted";
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
    "credentials"
    "dns"
    "expose"
    "hostForwards"
    "hostIp"
    "ip"
    "mac"
    "mem"
    "name"
    "prefixLength"
    "secretNames"
    "sshKeys"
    "stateSize"
    "tap"
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
  units.services."sbx-egress-proxy".serviceConfig.AmbientCapabilities == "CAP_NET_BIND_SERVICE"
  && lib.hasInfix "10.30.1.0/24" (
    toString units.services."sbx-egress-proxy".serviceConfig.IPAddressAllow
  )
  &&
    occurrences ''ip daddr 10.30.1.1 udp dport 53 counter accept comment "fencr:sbx:egress-dns"'' == 1
  &&
    occurrences ''ip daddr 10.30.1.1 tcp dport 443 counter accept comment "fencr:sbx:egress-tls"'' == 1
) "unit check: egress proxy is not the vm's road out";
assert lib.assertMsg (
  occurrences "priority filter - 1;" == 2
  && occurrences ''iifname "br-sbx" meta nfproto ipv6 drop'' == 2
) "core check: seal chain priority or v6 drop drifted";
assert lib.assertMsg (
  unknownCredential.errors == [ "sbx: credential \"nope\" is not declared in fencr.credentials" ]
) "core check: unknown credential accepted";
assert lib.assertMsg (
  resolved.guest.credentials.api.port == 14000
) "core check: credential port not in the guest contract";
assert lib.assertMsg (
  builtins.attrNames units.sockets == [
    "sbx-forward-33627"
    "sbx-host-forward-14000"
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
  units.services."sbx-credential-api".serviceConfig.RuntimeDirectory == "fencr-credential-sbx-api"
  && units.services."sbx-credential-api".serviceConfig.Group == "kvm"
  &&
    lib.hasSuffix "unix:/run/fencr-credential-sbx-api/credential.sock"
      units.services."sbx-host-forward-14000@".serviceConfig.ExecStart
) "unit check: credential proxy is not on its unix socket";
assert lib.assertMsg (lib.hasInfix "reverse_proxy https://api.example.com" (
  builtins.readFile (
    core.credentialCaddyfile pkgs "/run/x/credential.sock"
      (lib.findFirst (forward: forward.credential != null) null resolved.guest.hostForwards).credential
  )
)) "unit check: credential proxy does not originate tls to its upstream";
pkgs.writeText "fencr-core-check" (builtins.toJSON units.unitNames)
