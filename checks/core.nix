_self: pkgs:

# Probes the builders in modules/core without a host: instance derivation,
# the seal text and the host units. Nothing is built.
let
  inherit (pkgs) lib;
  core = import ../modules/core { inherit lib; };
  resolve =
    name: options:
    core.resolveInstance {
      inherit name;
      credentials = {
        api = {
          upstream = "https://api.example.com";
          domain = null;
          header = "Authorization";
          secretFile = "/run/secrets/api-token";
        };
        local = {
          upstream = "http://127.0.0.1:8764";
          domain = null;
          header = "Authorization";
          secretFile = "/run/secrets/local-token";
        };
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
  loopbackCredential = resolve "sbx" {
    id = 0;
    credentials = [ "local" ];
  };
  # a credential alone brings the egress proxy, but not its resolver
  keyed = resolve "keyed" {
    id = 2;
    egress = "open";
    credentials = [ "api" ];
  };
  keyedUnits = core.hostUnits pkgs keyed;
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
    "credentialDomains"
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
  !(units.services."fencr-sbx-egress-proxy".serviceConfig ? AmbientCapabilities)
  &&
    lib.hasPrefix "${core.egressProxyBin pkgs}/bin/fencr-egress-proxy 10.30.1.1:33053 10.30.1.1:33443 "
      units.services."fencr-sbx-egress-proxy".serviceConfig.ExecStart
  && lib.hasInfix "10.30.1.0/24" (
    toString units.services."fencr-sbx-egress-proxy".serviceConfig.IPAddressAllow
  )
  && occurrences "ip daddr 10.30.1.1 udp dport 53 redirect to :33053" == 1
  && occurrences "ip daddr 10.30.1.1 tcp dport 443 redirect to :33443" == 1
  &&
    occurrences ''ip daddr 10.30.1.1 udp dport 33053 counter accept comment "fencr:sbx:egress-dns"''
    == 1
  &&
    occurrences ''ip daddr 10.30.1.1 tcp dport 33443 counter accept comment "fencr:sbx:egress-tls"''
    == 1
) "unit check: egress proxy is not the vm's road out";
assert lib.assertMsg (
  occurrences "priority filter - 1;" == 2
  && occurrences ''iifname "br-sbx" meta nfproto ipv6 drop'' == 2
) "core check: seal chain priority or v6 drop drifted";
assert lib.assertMsg (
  unknownCredential.errors == [ "sbx: credential \"nope\" is not declared in fencr.credentials" ]
) "core check: unknown credential accepted";
assert lib.assertMsg (
  resolved.guest.credentialDomains == [ "api.example.com" ]
  &&
    loopbackCredential.errors == [
      "sbx: credential \"local\" needs fencr.credentials.local.domain: its upstream \"http://127.0.0.1:8764\" names no host a vm could call"
    ]
) "core check: credential domain drifted";
assert lib.assertMsg (
  keyed.proxy
  && !keyed.dnsProxy
  && keyed.guest.dns == "9.9.9.9"
  && keyedUnits.services ? "fencr-keyed-egress-proxy"
  && keyedUnits.services."fencr-keyed-egress-proxy".wants == [ "fencr-keyed-credentials.service" ]
  && keyedUnits.sockets ? "fencr-keyed-secrets"
  &&
    keyedUnits.services."fencr-keyed-secrets@".serviceConfig.LoadCredential == [
      "fencr-ca.crt:/var/lib/fencr/ca/root.crt"
    ]
  &&
    lib.hasInfix ''ip daddr 10.30.3.1 tcp dport 33443 counter accept comment "fencr:keyed:egress-tls"''
      (core.firewallOf keyed)."fencr-keyed".content
  && !lib.hasInfix "egress-dns" (core.firewallOf keyed)."fencr-keyed".content
  && lib.hasInfix "tcp dport 443 redirect to :33443" (core.firewallOf keyed)."fencr-keyed-nat".content
  && !lib.hasInfix "udp dport 53 redirect" (core.firewallOf keyed)."fencr-keyed-nat".content
) "core check: a credential alone does not bring the interception path";
assert lib.assertMsg (
  builtins.attrNames units.sockets == [
    "fencr-sbx-forward-33627"
    "fencr-sbx-host-forward-18764"
    "fencr-sbx-secrets"
  ]
  && units.sockets."fencr-sbx-forward-33627".socketConfig.ListenStream == "127.0.0.1:33627"
  &&
    units.sockets."fencr-sbx-host-forward-18764".socketConfig.ListenStream
    == "/run/fencr-sbx/vsock_18764"
  && units.sockets."fencr-sbx-host-forward-18764".socketConfig.SocketUser == "fencr-sbx"
  && units.sockets."fencr-sbx-host-forward-18764".socketConfig.SocketMode == "0600"
  && units.sockets."fencr-sbx-host-forward-18764".socketConfig.TriggerLimitIntervalSec == 0
) "unit check: host sockets drifted";
assert lib.assertMsg (
  lib.hasSuffix "connect /run/fencr-sbx/vsock 33627"
    units.services."fencr-sbx-forward-33627@".serviceConfig.ExecStart
  && lib.hasSuffix "serve 8764" units.services."fencr-sbx-host-forward-18764@".serviceConfig.ExecStart
) "unit check: relays do not use the vm's vsock socket";
assert lib.assertMsg (
  units.services."fencr-sbx-forward-33627@".after == [ "fencr-sbx.service" ]
  && units.services."fencr-sbx-forward-33627@".requisite == [ "fencr-sbx.service" ]
  && units.services."fencr-sbx-host-forward-18764@".partOf == [ "fencr-sbx.service" ]
  && !(units.services."fencr-sbx-forward-33627@" ? requires)
  && units.services."fencr-sbx-forward-33627@".serviceConfig.DynamicUser
) "unit check: forward relay drifted";
assert lib.assertMsg (
  units.services."fencr-sbx-credentials".serviceConfig.RuntimeDirectory == "fencr-credentials-sbx"
  && units.services."fencr-sbx-credentials".serviceConfig.Group == "kvm"
  && units.services."fencr-sbx-credentials".requires == [ "fencr-ca.service" ]
  &&
    units.services."fencr-sbx-credentials".serviceConfig.LoadCredential == [
      "api:/run/secrets/api-token"
      "ca.crt:/var/lib/fencr/ca/root.crt"
      "ca.key:/var/lib/fencr/ca/root.key"
    ]
  && units.services."fencr-sbx-egress-proxy".serviceConfig.Group == "kvm"
  && lib.hasInfix "api.example.com /run/fencr-credentials-sbx/credentials.sock" (
    builtins.readFile (
      lib.last (lib.splitString " " units.services."fencr-sbx-egress-proxy".serviceConfig.ExecStart)
    )
  )
) "unit check: credential proxy is not behind the egress proxy on its unix socket";
assert lib.assertMsg (
  let
    caddyfile = builtins.readFile (
      core.credentialCaddyfile pkgs "/run/x/credentials.sock" (
        resolved.credentials
        ++ [
          {
            name = "second";
            domain = "second.example.com";
            upstream = "http://127.0.0.1:1";
            header = "x-key";
          }
        ]
      )
    );
  in
  lib.hasInfix "https://api.example.com {" caddyfile
  && lib.hasInfix "https://second.example.com {" caddyfile
  && lib.hasInfix "tls internal" caddyfile
  && lib.hasInfix "reverse_proxy https://api.example.com" caddyfile
  && lib.hasInfix ''header_up Authorization "{$FENCR_CREDENTIAL_0}"'' caddyfile
  && lib.hasInfix ''header_up x-key "{$FENCR_CREDENTIAL_1}"'' caddyfile
) "unit check: credential proxy does not end tls for every granted domain with its own header";
pkgs.writeText "fencr-core-check" (builtins.toJSON units.unitNames)
