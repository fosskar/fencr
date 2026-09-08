_self: pkgs:

# Probes the builders in modules/core without a host: instance derivation,
# the firewall text and the host units. Nothing is built.
let
  inherit (pkgs) lib;
  core = import ../modules/core { inherit lib; };
  resolve =
    name: options:
    core.resolveInstance {
      inherit name;
      sshKeys = [ "ssh-ed25519 AAAA check" ];
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
      inherit options;
    };
  resolved = resolve "sbx" {
    id = 0;
    outbound = [
      "github.com"
      "192.168.1.50:8123"
      "host:443"
    ];
    inbound = [ 33627 ];
    credentials = [ "api" ];
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
    credentials = [ "api" ];
  };
  keyedUnits = core.hostUnits pkgs keyed;
  units = core.hostUnits pkgs resolved;
  longName = resolve "coding-agent-1" {
    id = 1;
    outbound = [ "internet" ];
  };
  samePort = resolve "sbx" {
    id = 0;
    inbound = [
      22100
      22100
    ];
  };
  tables = core.firewallOf resolved;
  filterTable = tables."fencr-sbx".content;
  natTable = tables."fencr-sbx-nat".content;
  rendered = filterTable + natTable;
  occurrences = needle: lib.length (lib.splitString needle rendered) - 1;
  check =
    label: actual: expected:
    lib.assertMsg (
      actual == expected
    ) "core check: ${label}: expected ${builtins.toJSON expected}, got ${builtins.toJSON actual}";
  invalidOutbound =
    entry: message:
    check "outbound ${builtins.toJSON entry} errors"
      (resolve "sbx" {
        id = 0;
        outbound = [ entry ];
      }).errors
      [ "sbx: outbound entry \"${entry}\": ${message}" ];
  outboundValue =
    entry: expected:
    check "outbound ${builtins.toJSON entry} value" (core.parseOutbound entry).value expected;
  outboundKind =
    entry: expected:
    check "outbound ${builtins.toJSON entry} kind" (core.parseOutbound entry).kind expected;
  legacyPolicy = resolved // {
    egress = "closed";
    allowedDomains = [ "github.com" ];
    allowedTCPDestinations = [
      {
        address = "192.168.1.50";
        port = 8123;
      }
    ];
    hostPorts = [ 443 ];
    expose = [ 33627 ];
    proxy = true;
    dnsProxy = true;
    hostDns = false;
  };
in
assert lib.assertMsg (
  core.forwardRules resolved == core.forwardRules legacyPolicy
  && core.inputRules resolved == core.inputRules legacyPolicy
  && core.outputRules resolved == core.outputRules legacyPolicy
  && core.redirectRules resolved == core.redirectRules legacyPolicy
  && core.egressProxyServiceConfig pkgs resolved == core.egressProxyServiceConfig pkgs legacyPolicy
) "core check: access syntax changed enforcement";
assert check "internet and domain grants"
  (resolve "sbx" {
    id = 0;
    outbound = [
      "internet"
      "github.com"
    ];
  }).errors
  [ "sbx: outbound cannot combine internet with domain grants" ];
assert (
  invalidOutbound "host" "host needs a port; expected host:<port>"
  && invalidOutbound "1.2.3.4" "an address needs a port"
  && invalidOutbound "example.123" "an address needs a port"
  && invalidOutbound "300.1.1.1:80" "octet out of range"
  && invalidOutbound "1.2.3:80" "expected a dotted-quad IPv4 address"
  && invalidOutbound "1.2.3.4/33:80" "prefix must be between 0 and 32"
  && invalidOutbound "1.2.3.4/24/1:80" "prefix must be between 0 and 32"
  && lib.all (entry: invalidOutbound entry "port must be between 1 and 65535") [
    "host:0"
    "host:65536"
    "1.2.3.4:0"
    "1.2.3.4:65536"
  ]
  && lib.all (entry: invalidOutbound entry "port must be a decimal integer") [
    "host:no"
    "1.2.3.4:no"
  ]
  && lib.all (entry: invalidOutbound entry "missing port") [
    "host:"
    "1.2.3.4:"
  ]
  && lib.all (entry: invalidOutbound entry "expected one colon separating the destination and port") [
    "host:8080:1"
    "1.2.3.4:80:1"
  ]
  && invalidOutbound "1.2.3.4/99999999999999999999:80" "prefix must be between 0 and 32"
  && invalidOutbound "99999999999999999999.1.1.1:80" "octet out of range"
  && invalidOutbound "localhost" ''"localhost": not a hostname pattern; expected "example.com" or "*.example.com"''
  && invalidOutbound "github.com:443" "expected host:<port> or <ipv4[/prefix]>:<port>; domains use TLS on 443 without a port"
);
assert check "internet with host and subnet grants"
  (resolve "sbx" {
    id = 0;
    outbound = [
      "internet"
      "host:8080"
      "192.168.20.0/24:1234"
    ];
  }).errors
  [ ];
assert (
  outboundValue "192.168.20.0/24:1234" {
    address = "192.168.20.0/24";
    port = 1234;
  }
  && outboundValue "010.001.002.003/08:080" {
    address = "10.1.2.3/8";
    port = 80;
  }
  && outboundValue "host:080" 80
  && outboundValue "0255.1.1.1:80" {
    address = "255.1.1.1";
    port = 80;
  }
  && outboundValue "host:00000000000000000000080" 80
  && outboundKind "example.host" "domain"
  && outboundKind "*.github.com" "domain"
  && outboundKind "0.0.0.0/0:1" "tcp"
  && outboundKind "255.255.255.255/32:65535" "tcp"
);
assert lib.assertMsg (
  !(builtins.tryEval (
    builtins.deepSeq
      (lib.evalModules {
        modules = [
          ../modules/nixos/options.nix
          {
            fencr.vms.sbx = {
              id = 0;
              inbound = [ "9119" ];
            };
          }
        ];
      }).config.fencr.vms.sbx.inbound
      true
  )).success
) "core check: inbound accepted a string port";
assert lib.assertMsg (resolved.cid == 3) "core check: wrong cid";
assert lib.assertMsg (resolved.ip == "10.11.0.2") "core check: wrong guest address";
assert lib.assertMsg (resolved.expose == [ 33627 ]) "core check: inbound was not resolved";
assert lib.assertMsg (
  resolved.memoryMax == "4608M"
  &&
    (resolve "sbx" {
      id = 0;
      mem = 8192;
    }).memoryMax == "8704M"
  &&
    (resolve "sbx" {
      id = 0;
      memoryMax = "1G";
    }).memoryMax == "1G"
) "core check: the unit's cap does not follow the guest's memory";
assert lib.assertMsg (
  resolved.proxy
  && resolved.guest.dns == "10.11.0.1"
  && !longName.proxy
  && longName.hostDns
  && longName.guest.dns == "10.11.1.1"
  && !(resolve "sbx" { id = 0; }).hostDns
  && (resolve "sbx" { id = 0; }).guest.dns == null
) "core check: the host is not the guest's resolver";
assert lib.assertMsg (
  longName.errors
  == [ "vm name \"coding-agent-1\" is too long: \"tap-coding-agent-1\" exceeds IFNAMSIZ" ]
) "core check: long interface name accepted";
assert lib.assertMsg (
  lib.hasInfix ''ip daddr 10.11.1.1 udp dport 53 counter accept comment "fencr:coding-agent-1:dns"''
    (core.firewallOf longName)."fencr-coding-agent-1".content
  && !lib.hasInfix "dport 53 " filterTable
) "core check: open egress does not admit the host's resolver on the bridge";
assert lib.assertMsg (
  samePort.errors == [ "sbx: inbound port 22100 declared twice" ]
) "core check: repeated inbound port accepted";
assert lib.assertMsg (
  core.fleetErrors {
    first = resolved;
    second = resolved;
  } == [ "instance id 0 is shared by first, second; set id on one of them" ]
) "core check: duplicate instance id accepted";
assert lib.assertMsg (
  let
    names = [
      "zed"
      "alpha"
      "mid"
    ];
    last = resolve "zed" { id = core.idOf names "zed"; };
    top = resolve "top" { id = 255; };
  in
  core.idOf names "alpha" == 0
  && core.idOf names "mid" == 1
  && last.id == 2
  && last.ip == "10.11.2.2"
  && last.mac == "02:00:00:00:20:02"
  && top.mac == "02:00:00:00:20:ff"
  && top.cid == 258
  && (resolve "sbx" { id = 256; }).errors == [ "sbx: id must be between 0 and 255" ]
) "core check: id from name order";
assert lib.assertMsg (
  builtins.attrNames resolved.guest == [
    "bridge"
    "cid"
    "credentialDomains"
    "dns"
    "expose"
    "hostIp"
    "ip"
    "mac"
    "mem"
    "name"
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
) core.specialUseNetworks.v4) "core check: open egress does not block every special-use range";
assert lib.assertMsg (
  !(units.services."fencr-sbx-egress-proxy".serviceConfig ? AmbientCapabilities)
  &&
    lib.hasPrefix "${core.egressProxyBin pkgs}/bin/fencr-egress-proxy 10.11.0.1:33053 10.11.0.1:33443 "
      units.services."fencr-sbx-egress-proxy".serviceConfig.ExecStart
  &&
    units.services."fencr-sbx-egress-proxy".serviceConfig.IPAddressAllow == [
      "127.0.0.53/32"
      "10.11.0.0/26"
    ]
  && !lib.elem "0.0.0.0/0" units.services."fencr-sbx-credentials".serviceConfig.IPAddressAllow
  && occurrences ''iifname "br-sbx" tcp dport { 443 } counter accept comment "fencr:sbx:host"'' == 1
  &&
    occurrences ''iifname "br-sbx" ip daddr 192.168.1.50 tcp dport 8123 counter accept comment "fencr:sbx:pin-192.168.1.50-8123"''
    == 1
  && occurrences "ip daddr 10.11.0.1 udp dport 53 redirect to :33053" == 1
  && occurrences "ip daddr 10.11.0.1 tcp dport 443 redirect to :33443" == 1
  &&
    occurrences ''ip daddr 10.11.0.1 udp dport 33053 counter accept comment "fencr:sbx:egress-dns"''
    == 1
  &&
    occurrences ''ip daddr 10.11.0.1 tcp dport 33443 counter accept comment "fencr:sbx:egress-tls"''
    == 1
) "unit check: egress proxy is not the vm's road out";
assert lib.assertMsg (
  units.services."fencr-sbx-egress-proxy".serviceConfig.SystemCallFilter == [
    "@system-service"
    "~@privileged"
    "~@resources"
  ]
  &&
    units.services."fencr-sbx-credentials".serviceConfig.SystemCallFilter == [
      "@system-service"
      "~@privileged"
      "~@resources"
    ]
  && !((core.vmService pkgs resolved "/nix/store/runner").serviceConfig ? SystemCallFilter)
) "core check: syscall filter drifted";
assert lib.assertMsg (
  occurrences "priority filter - 1;" == 3
  && occurrences ''iifname "br-sbx" meta nfproto ipv6 drop'' == 2
  && occurrences ''oifname "br-sbx" meta nfproto ipv6 drop'' == 1
) "core check: chain priority or v6 drop drifted";
assert lib.assertMsg (
  unknownCredential.errors == [ "sbx: credential \"nope\" is not declared in fencr.credentials" ]
) "core check: unknown credential accepted";
assert lib.assertMsg (
  (core.resolveInstance {
    name = "sbx";
    credentials = lib.genAttrs [ "ca.key" "api:key" ] (credentialName: {
      upstream = "https://api.example.com";
      domain = "${lib.replaceStrings [ ":" ] [ "-" ] credentialName}.example.com";
      header = "Authorization";
      secretFile = "/run/secrets/api-token";
    });
    options = {
      id = 0;
      credentials = [
        "ca.key"
        "api:key"
      ];
      secrets."fencr-ca.crt" = "/run/secrets/raw";
    };
  }).errors == [
    "sbx: secret name \"fencr-ca.crt\" is reserved for the authority"
    "sbx: credential name \"api:key\" contains characters unsupported by systemd credentials"
    "sbx: credential name \"ca.key\" is reserved for the authority"
  ]
) "core check: a name the authority uses was accepted";
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
  && keyed.guest.dns == null
  && keyedUnits.services ? "fencr-keyed-egress-proxy"
  && keyedUnits.services."fencr-keyed-egress-proxy".wants == [ "fencr-keyed-credentials.service" ]
  && keyedUnits.sockets ? "fencr-keyed-secrets"
  &&
    keyedUnits.services."fencr-keyed-secrets@".serviceConfig.LoadCredential == [
      "fencr-ca.crt:/var/lib/fencr/ca/root.crt"
    ]
  &&
    lib.hasInfix ''ip daddr 10.11.2.1 tcp dport 33443 counter accept comment "fencr:keyed:egress-tls"''
      (core.firewallOf keyed)."fencr-keyed".content
  && !lib.hasInfix "egress-dns" (core.firewallOf keyed)."fencr-keyed".content
  && lib.hasInfix "tcp dport 443 redirect to :33443" (core.firewallOf keyed)."fencr-keyed-nat".content
  && !lib.hasInfix "udp dport 53 redirect" (core.firewallOf keyed)."fencr-keyed-nat".content
) "core check: a credential alone does not bring the interception path";
assert lib.assertMsg (
  builtins.attrNames units.sockets == [ "fencr-sbx-secrets" ]
  && units.sockets."fencr-sbx-secrets".socketConfig.ListenStream == "/run/fencr-sbx/vsock_5"
  && units.sockets."fencr-sbx-secrets".socketConfig.SocketUser == "fencr-sbx"
  && units.sockets."fencr-sbx-secrets".socketConfig.SocketMode == "0600"
) "unit check: host sockets drifted";
assert lib.assertMsg (
  units.services."fencr-sbx-secrets@".after == [
    "fencr-sbx.service"
    "fencr-ca.service"
  ]
  && units.services."fencr-sbx-secrets@".requisite == [ "fencr-sbx.service" ]
  && units.services."fencr-sbx-secrets@".partOf == [ "fencr-sbx.service" ]
  && units.services."fencr-sbx-secrets@".serviceConfig.DynamicUser
) "unit check: secrets relay drifted";
assert lib.assertMsg (
  occurrences ''oifname "br-sbx" ip daddr 10.11.0.2 tcp dport { 22, 33627 } counter accept comment "fencr:sbx:guest"''
  == 1
  && occurrences ''oifname "br-sbx" counter drop comment "fencr:sbx:guest-blocked"'' == 1
) "core check: the host is not held to the guest's sshd and exposed ports";
assert lib.assertMsg (
  units.services."fencr-sbx-credentials".serviceConfig.RuntimeDirectory == "fencr-sbx-credentials"
  && units.services."fencr-sbx-credentials".serviceConfig.Group == "kvm"
  && units.services."fencr-sbx-credentials".requires == [ "fencr-ca.service" ]
  &&
    units.services."fencr-sbx-credentials".serviceConfig.LoadCredential == [
      "api:/run/secrets/api-token"
      "ca.crt:/var/lib/fencr/ca/root.crt"
      "ca.key:/var/lib/fencr/ca/root.key"
    ]
  && units.services."fencr-sbx-egress-proxy".serviceConfig.Group == "kvm"
  &&
    lib.hasSuffix " /run/fencr-sbx-credentials/credentials.sock"
      units.services."fencr-sbx-egress-proxy".serviceConfig.ExecStart
) "unit check: credential proxy is not behind the egress proxy on its unix socket";
assert lib.assertMsg (
  let
    caddyfile = core.credentialCaddyfile "/run/x/credentials.sock" (
      resolved.credentials
      ++ [
        {
          name = "second";
          domain = "second.example.com";
          upstream = "http://127.0.0.1:1";
          header = "x-key";
        }
      ]
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
