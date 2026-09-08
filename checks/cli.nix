_self: pkgs:
let
  inherit (pkgs) lib;
  core = import ../modules/core { inherit lib; };
  credentials.api = {
    upstream = "http://127.0.0.1:8764";
    domain = "api.test";
    header = "Authorization";
    secretFile = "/run/secrets/api-token";
  };
  instance = core.resolveInstance {
    name = "sbx";
    sshKeys = [ "ssh-ed25519 AAAA check" ];
    inherit credentials;
    options = {
      id = 0;
      outbound = [ "github.com" ];
      inbound = [ 33627 ];
      credentials = [ "api" ];
    };
  };
  instances = {
    sbx = instance;
    inherit sealed open keyed;
  };
  sealed = core.resolveInstance {
    name = "sealed";
    options.id = 1;
  };
  open = core.resolveInstance {
    name = "open";
    options = {
      id = 2;
      outbound = [
        "internet"
        "host:8080"
        "192.168.20.0/24:1234"
      ];
    };
  };
  keyed = core.resolveInstance {
    name = "keyed";
    inherit credentials;
    options = {
      id = 3;
      credentials = [ "api" ];
    };
  };
  systemctl = pkgs.writeShellScriptBin "systemctl" ''
    set -eu
    printf '%s\n' "$*" >> "$TEST_LOG"
    case "$TEST_STATE" in
      unavailable) exit 1 ;;
      missing) printf 'LoadState=not-found\n'; exit 0 ;;
    esac
    printf 'LoadState=loaded\nActiveState=%s\nMemoryCurrent=1048576\nActiveEnterTimestamp=Tue 2026-09-08 05:11:18 UTC\n' "$TEST_STATE"
  '';
  # the ruleset the command parses is the one core renders, as nft lists it
  # back: every counter at three packets, and the burst nft adds to a rate
  # limit, since "packets" is the token the parser keys on. the traffic
  # line then sums the same comment tags the firewall wrote
  ruleset = pkgs.writeText "fencr-test-ruleset" (
    builtins.replaceStrings
      [ " counter " " limit rate 5/second log " ]
      [ " counter packets 3 bytes 300 " " limit rate 5/second burst 5 packets log " ]
      (lib.concatStrings (lib.mapAttrsToList (_: table: table.content) (core.firewallOf instance)))
  );
  nft = pkgs.writeShellScriptBin "nft" ''
    cat ${ruleset}
  '';
  # the kernel log for denials since the vm started, on every drop chain,
  # with the host's igmp report and a stale reply; the proxy's own log for
  # domains
  journalctl = pkgs.writeShellScriptBin "journalctl" ''
    printf '%s\n' "$*" >> "$TEST_LOG"
    case "$1" in
      -k)
        # -g with no match exits 1 and prints nothing
        [ "''${TEST_QUIET-}" = 1 ] && exit 1
        printf 'fencr:sbx:blocked: IN=br-sbx OUT=eth0 SRC=10.11.0.2 DST=1.2.3.4 PROTO=TCP DPT=443\n'
        printf 'fencr:sbx:blocked: IN=br-sbx OUT=eth0 SRC=10.11.0.2 DST=1.2.3.4 PROTO=TCP DPT=443\n'
        printf 'fencr:sbx:guest-blocked: IN= OUT=br-sbx SRC=10.11.0.1 DST=10.11.0.2 PROTO=TCP DPT=9120\n'
        printf 'fencr:sbx:guest-blocked: IN= OUT=br-sbx SRC=10.11.0.1 DST=224.0.0.22 PROTO=2\n'
        printf 'fencr:sbx:host-blocked: IN=br-sbx OUT= SRC=10.11.0.2 DST=10.11.0.1 PROTO=TCP SPT=33627 DPT=58836\n'
        ;;
      -u)
        printf 'allow github.com\ndeny evil.test\nintercept api.test\n'
        ;;
    esac
  '';
  cli = import ../modules/cli.nix {
    inherit lib;
    pkgs = pkgs // {
      systemd = pkgs.symlinkJoin {
        name = "fencr-test-systemd";
        paths = [
          systemctl
          journalctl
        ];
      };
      nftables = nft;
    };
    inherit instances;
    units = lib.mapAttrs (_: core.hostUnits pkgs) instances;
  };
in
pkgs.runCommand "fencr-cli-check" { } ''
  export TEST_LOG="$PWD/queries"
  export TEST_STATE=active
  ${cli}/bin/fencr status sbx > actual
  cat > expected <<'EOF'
  sbx  RUNNING  10.11.0.2  memory 1M
  Inbound (from host):
    ✓ TCP 22, 33627 (22: ssh)                   3 packets
  Outbound (otherwise denied):
    ✓ github.com TLS 443                        1 connection
    ✓ api.test TLS 443 (credential api)         1 connection

  Blocked (journal):
    ✗ guest → 1.2.3.4:443/tcp           x2     outbound "1.2.3.4:443"
    ✗ guest → evil.test:443/tls         x1     outbound "evil.test"
    ✗ guest → host:58836/tcp            x1     reply to a connection the host no longer tracks
    ✗ host  → guest:9120/tcp            x1     inbound 9120

  Services: egress proxy RUNNING, credential RUNNING

  EOF
  diff -u expected actual
  cat > expected-queries <<'EOF'
  show fencr-sbx.service --property=LoadState,ActiveState,MemoryCurrent,ActiveEnterTimestamp
  -k -q --no-pager -g fencr: -o cat --since Tue 2026-09-08 05:11:18 UTC
  -u fencr-sbx-egress-proxy.service -q -n 400 --no-pager -o cat
  show fencr-sbx-egress-proxy.service --property=LoadState,ActiveState
  show fencr-sbx-credentials.service --property=LoadState,ActiveState
  EOF
  diff -u expected-queries "$TEST_LOG"
  TEST_QUIET=1 ${cli}/bin/fencr status sbx > actual
  grep -Fx '  ✗ guest → evil.test:443/tls         x1     outbound "evil.test"' actual
  if grep -F '1.2.3.4' actual; then exit 1; fi
  ${cli}/bin/fencr status sbx --full > /dev/null
  grep -Fx "status fencr-sbx.service fencr-sbx-egress-proxy.service fencr-sbx-credentials.service --no-pager" "$TEST_LOG"
  ${cli}/bin/fencr status sealed > actual
  test "$(grep -c '^  denied$' actual)" = 2
  ${cli}/bin/fencr status open > actual
  grep -Fx '  · public IPv4 internet and DNS (special-use ranges excluded)  unused' actual
  grep -Fx '  · host TCP 8080                             unused' actual
  grep -Fx '  · 192.168.20.0/24 TCP 1234                  unused' actual
  grep -Fx '  none' actual
  ${cli}/bin/fencr status keyed > actual
  grep -Fx '  ✓ api.test TLS 443 (credential api)         1 connection' actual
  if grep -F 'github.com TLS 443' actual; then exit 1; fi
  ${cli}/bin/fencr list > actual
  grep -E '^sealed +1 +4 +10.11.1.2 +denied / denied$' actual
  grep -F 'TCP 22, 33627 (22: ssh) / github.com TLS 443, api.test TLS 443 (credential api)' actual
  for state in failed inactive missing unavailable; do
    export TEST_STATE="$state"
    case "$state" in
      failed) health=FAILED ;;
      inactive) health=STOPPED ;;
      missing) health=MISSING ;;
      unavailable) health="unavailable: exit status: 1" ;;
    esac
    ${cli}/bin/fencr status sbx > actual
    grep -F "sbx  $health  10.11.0.2" actual
    grep -Fx "Services: egress proxy $health, credential $health" actual
  done
  touch "$out"
''
