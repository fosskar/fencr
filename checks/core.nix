_self: pkgs:

# Probes the builders in modules/core without a host. Nothing is built.
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
in
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
  && invalidOutbound "300.1.1.1:80" "octet out of range or written with a leading zero"
  && invalidOutbound "1.2.3:80" "expected a dotted-quad IPv4 address"
  && invalidOutbound "1.2.3.4/33:80" "prefix must be between 0 and 32, written without leading zeros"
  && invalidOutbound "1.2.3.4/24/1:80" "prefix must be between 0 and 32, written without leading zeros"
  &&
    lib.all
      (entry: invalidOutbound entry "port must be between 1 and 65535, written without leading zeros")
      [
        "host:0"
        "host:65536"
        "host:080"
        "host:00000000000000000000080"
        "host:no"
        "1.2.3.4:0"
        "1.2.3.4:65536"
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
  && invalidOutbound "1.2.3.4/99999999999999999999:80" "prefix must be between 0 and 32, written without leading zeros"
  && invalidOutbound "99999999999999999999.1.1.1:80" "octet out of range or written with a leading zero"
  && invalidOutbound "010.001.002.003/08:080" "octet out of range or written with a leading zero"
  && invalidOutbound "0255.1.1.1:80" "octet out of range or written with a leading zero"
  && invalidOutbound "1.2.3.4/08:80" "prefix must be between 0 and 32, written without leading zeros"
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
  && outboundKind "example.host" "domain"
  && outboundKind "*.github.com" "domain"
  && outboundKind "0.0.0.0/0:1" "tcp"
  && outboundKind "255.255.255.255/32:65535" "tcp"
  && outboundKind "!gist.github.com" "deny"
  && outboundValue "!*.raw.github.com" "*.raw.github.com"
);
assert check "deny entries under a wildcard grant"
  (resolve "sbx" {
    id = 0;
    outbound = [
      "*.github.com"
      "github.com"
      "!gist.github.com"
      "!*.raw.github.com"
    ];
  }).denied
  [
    "gist.github.com"
    "*.raw.github.com"
  ];
assert check "deny entries no grant covers"
  (resolve "sbx" {
    id = 0;
    outbound = [
      "github.com"
      "!gist.github.com"
      "!github.com"
      "!*github.com"
    ];
  }).errors
  [
    "sbx: outbound entry \"!*github.com\": a deny entry names a domain pattern; \"*github.com\": a wildcard must be its own label (\"*.example.com\"); \"*example.com\" also matches evilexample.com"
    "sbx: outbound entry \"!github.com\" denies the whole grant \"github.com\""
    "sbx: outbound entry \"!gist.github.com\" denies nothing: no domain grant covers gist.github.com"
  ];
assert check "deny entry with internet"
  (resolve "sbx" {
    id = 0;
    outbound = [
      "internet"
      "!gist.github.com"
    ];
  }).errors
  [
    "sbx: outbound entry \"!gist.github.com\" denies nothing: no domain grant covers gist.github.com"
  ];
assert lib.assertMsg (
  !(builtins.tryEval (
    builtins.deepSeq
      (lib.evalModules {
        modules = [
          ../modules/options.nix
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
assert lib.assertMsg (resolved.inbound == [ 33627 ]) "core check: inbound was not resolved";
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
  let
    cap = ''iifname "br-sbx" ct state new ct count over 2048 counter drop comment "fencr:sbx:connections-blocked"'';
    capped = resolve "sbx" {
      id = 0;
      maxConnections = 16;
      diskBandwidth = 200;
      networkBandwidth = 50;
    };
  in
  lib.hasInfix cap (core.forwardRules resolved)
  && lib.hasInfix cap (core.inputRules resolved)
  && lib.hasInfix "ct count over 16 " (core.forwardRules capped)
  && resolved.diskBandwidth == null
  && resolved.networkBandwidth == null
  && capped.diskBandwidth == 200
  && capped.networkBandwidth == 50
) "core check: the resource caps are not rendered";
assert lib.assertMsg (
  resolved.proxy
  && resolved.dns == "10.11.0.1"
  && !longName.proxy
  && longName.hostDns
  && longName.dns == "10.11.1.1"
  && !(resolve "sbx" { id = 0; }).hostDns
  && (resolve "sbx" { id = 0; }).dns == null
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
  core.hostErrors {
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
  builtins.attrNames (core.guestOf resolved) == [
    "bridge"
    "cid"
    "credentialDomains"
    "credentialEnv"
    "credentialPlaceholders"
    "diskBandwidth"
    "dns"
    "hostIp"
    "inbound"
    "ip"
    "mac"
    "mem"
    "name"
    "networkBandwidth"
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
# the unit's own user, no capabilities, and the empty root the jailer builds
assert lib.assertMsg (
  let
    vm = (core.vmService pkgs resolved "/nix/store/runner").serviceConfig;
  in
  vm.User == "fencr-sbx"
  && vm.CapabilityBoundingSet == ""
  && vm.RestrictSUIDSGID
  && vm.PrivateIPC
  && vm.TemporaryFileSystem == "/:ro"
  && vm.BindReadOnlyPaths == [ "/nix/store" ]
  &&
    vm.BindPaths == [
      "/run/fencr-sbx"
      "/var/lib/fencr-vms/sbx"
    ]
  && vm.ProtectProc == "invisible"
  && vm.ProcSubset == "pid"
  && !(vm ? ProtectSystem)
  && !(vm ? ProtectHome)
  && vm.DevicePolicy == "closed"
  && vm.IPAddressDeny == "any"
) "core check: hypervisor unit drifted";
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
  resolved.credentialDomains == [ "api.example.com" ]
  &&
    loopbackCredential.errors == [
      "sbx: credential \"local\" needs fencr.credentials.local.domain: its upstream \"http://127.0.0.1:8764\" names no host a vm could call"
    ]
) "core check: credential domain drifted";
assert lib.assertMsg (
  keyed.proxy
  && !keyed.dnsProxy
  && keyed.dns == null
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
# the placeholder: stable for a vm and credential, different per vm, in the
# guest's environment only where guestEnv names a variable
assert lib.assertMsg (
  let
    placeholder = core.placeholderOf "sbx" "api";
  in
  lib.hasPrefix "fencr-" placeholder
  && placeholder == core.placeholderOf "sbx" "api"
  && placeholder != core.placeholderOf "other" "api"
  && placeholder != core.placeholderOf "sbx" "other"
  && resolved.credentialPlaceholders == { api = placeholder; }
  && resolved.credentialEnv == { }
  && lib.hasInfix "uri replace ${placeholder} {file.{$CREDENTIALS_DIRECTORY}/api}" (
    core.credentialCaddyfile "/run/x/credentials.sock" resolved.credentials
  )
) "unit check: the credential placeholder drifted";
# a rotated secretFile reaches the proxies: one watcher for the host, and
# none at all where no credential is granted
assert lib.assertMsg (
  let
    reload = core.reloadUnits pkgs {
      inherit keyed;
      sbx = resolved;
      sealed = resolve "sealed" { id = 1; };
    };
  in
  reload.paths.fencr-credentials-reload.pathConfig == {
    PathChanged = [ "/run/secrets/api-token" ];
    PathModified = [ "/run/secrets/api-token" ];
  }
  && lib.hasSuffix "systemctl try-restart fencr-keyed-credentials.service fencr-sbx-credentials.service" reload.services.fencr-credentials-reload.serviceConfig.ExecStart
  && core.reloadUnits pkgs { sealed = resolve "sealed" { id = 1; }; } == { }
) "unit check: a rotated credential file does not reach the proxies";
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
          placeholder = "fencr-second-placeholder";
          header = "x-key";
        }
      ]
    );
  in
  lib.hasInfix "https://api.example.com {" caddyfile
  && lib.hasInfix "https://second.example.com {" caddyfile
  && lib.hasInfix "tls internal" caddyfile
  && lib.hasInfix "reverse_proxy https://api.example.com" caddyfile
  && lib.hasInfix ''header_up Authorization "{file.{$CREDENTIALS_DIRECTORY}/api}"'' caddyfile
  && lib.hasInfix ''header_up x-key "{file.{$CREDENTIALS_DIRECTORY}/second}"'' caddyfile
  && !lib.hasInfix "handle" caddyfile
) "unit check: credential proxy does not end tls for every granted domain with its own header";
assert lib.assertMsg (
  let
    caddyfile = core.credentialCaddyfile "/run/x/credentials.sock" [
      {
        name = "gh";
        domain = "api.github.com";
        upstream = "https://api.github.com";
        placeholder = "fencr-gh-placeholder";
        header = "Authorization";
        allow = [
          "GET,HEAD *"
          "POST /repos/*/pulls"
          "* /user"
        ];
      }
    ];
  in
  lib.hasInfix "  @allow0 {\n    method GET HEAD\n  }\n  handle @allow0 {\n    uri replace fencr-gh-placeholder {file.{$CREDENTIALS_DIRECTORY}/gh}\n    reverse_proxy https://api.github.com {" caddyfile
  && lib.hasInfix "  @allow1 {\n    method POST\n    path /repos/*/pulls\n  }\n" caddyfile
  && lib.hasInfix "  @allow2 {\n    path /user\n  }\n" caddyfile
  && lib.hasInfix "  handle @allow2 {" caddyfile
  && lib.hasInfix ''respond "fencr: request not allowed for credential gh" 403'' caddyfile
  &&
    lib.length (
      lib.splitString ''header_up Authorization "{file.{$CREDENTIALS_DIRECTORY}/gh}"'' caddyfile
    ) == 4
  &&
    (core.parseAllow "GET /x") == {
      methods = [ "GET" ];
      path = "/x";
      error = null;
    }
  &&
    (core.parseAllow "get /x").error
    == "\"get /x\": methods are upper-case names separated by commas, or \"*\""
  && (core.parseAllow "GET x").error == "\"GET x\": the path starts with \"/\", or is \"*\""
  && (core.parseAllow "GET").error == "\"GET\": expected \"<methods> <path>\""
  &&
    (core.resolveInstance {
      name = "sbx";
      credentials.api = {
        upstream = "https://api.example.com";
        domain = null;
        header = "Authorization";
        secretFile = "/run/secrets/api-token";
        allow = [ "GET" ];
      };
      options = {
        id = 0;
        credentials = [ "api" ];
      };
    }).errors == [ "sbx: credential \"api\": allow entry \"GET\": expected \"<methods> <path>\"" ]
) "unit check: credential allow entries are not rendered or validated";
assert lib.assertMsg (
  let
    template = units.services."fencr-sbx-checkpoint@".serviceConfig;
    script = core.checkpointText pkgs resolved;
    hourly = resolve "sbx" {
      id = 0;
      checkpoints.interval = "hourly";
      checkpoints.keep = 3;
    };
    timed = core.hostUnits pkgs hourly;
    silent = core.vmService pkgs (resolve "sbx" {
      id = 0;
      checkpoints.onStop = false;
    }) "/run/x";
  in
  template.User == "fencr-sbx"
  && template.TemporaryFileSystem == "/:ro"
  && lib.elem "/var/lib/fencr-vms/sbx" template.BindPaths
  && template.RestrictAddressFamilies == [ "AF_UNIX" ]
  && lib.hasSuffix " %i" template.ExecStart
  && lib.hasInfix "cp --reflink=always " script
  && lib.hasInfix "sync -f " script
  && lib.hasInfix "head -n -5 " script
  && lib.hasInfix "curl --silent --fail --unix-socket \"$socket\" http://localhost/" script
  && lib.hasInfix "/run/fencr-sbx/api.sock" script
  && units.timers == { }
  &&
    timed.timers.fencr-sbx-checkpoint.timerConfig == {
      OnCalendar = "hourly";
      Unit = "fencr-sbx-checkpoint@timer.service";
    }
  && lib.hasInfix "head -n -3 " (core.checkpointText pkgs hourly)
  &&
    lib.any (lib.hasSuffix " stop")
      (core.vmService pkgs resolved "/run/x").serviceConfig.ExecStopPost
  && silent.serviceConfig.ExecStopPost == [ ]
) "unit check: checkpoints are not wired";
pkgs.writeText "fencr-core-check" (builtins.toJSON (lib.attrNames units.services))
