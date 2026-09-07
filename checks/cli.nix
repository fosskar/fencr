_self: pkgs:
let
  inherit (pkgs) lib;
  core = import ../modules/core { inherit lib; };
  instance = core.resolveInstance {
    name = "sbx";
    credentials.api = {
      upstream = "http://127.0.0.1:8764";
      domain = "api.test";
      header = "Authorization";
      secretFile = "/run/secrets/api-token";
    };
    options = {
      id = 0;
      dns = "9.9.9.9";
      allowedDomains = [ "github.com" ];
      expose = [ "33627" ];
      credentials = [ "api" ];
    };
  };
  units = core.hostUnits pkgs instance;
  systemctl = pkgs.writeShellScriptBin "systemctl" ''
    set -eu
    printf '%s\n' "$*" >> "$TEST_LOG"
    case "$TEST_STATE" in
      unavailable) exit 1 ;;
      missing) printf 'LoadState=not-found\n'; exit 0 ;;
    esac
    printf 'LoadState=loaded\nActiveState=%s\nMemoryCurrent=1048576\n' "$TEST_STATE"
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
  # the kernel log for recent denials, on every drop chain; the proxy's
  # own log for domains
  journalctl = pkgs.writeShellScriptBin "journalctl" ''
    case "$1" in
      -k)
        printf 'fencr:sbx:blocked: IN=br-sbx OUT=eth0 SRC=10.30.1.2 DST=1.2.3.4 PROTO=TCP DPT=443\n'
        printf 'fencr:sbx:blocked: IN=br-sbx OUT=eth0 SRC=10.30.1.2 DST=1.2.3.4 PROTO=TCP DPT=443\n'
        printf 'fencr:sbx:guest-blocked: IN= OUT=br-sbx SRC=10.30.1.1 DST=10.30.1.2 PROTO=TCP DPT=9120\n'
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
    instances.sbx = instance;
    units.sbx = units;
  };
in
pkgs.runCommand "fencr-cli-check" { } ''
  export TEST_LOG="$PWD/queries"
  export TEST_STATE=active
  ${cli}/bin/fencr status sbx > actual
  cat > expected <<'EOF'
  sbx  RUNNING  10.30.1.2  memory 1M
  Internet: CLOSED

  Traffic:
    allowed  9 packets
    blocked  9 packets  (recent: 1.2.3.4:443/tcp x2, 10.30.1.2:9120/tcp x1)

  Domains: ✓ api.test (1, credential)  ✗ evil.test (1)  ✓ github.com (1)
  Services: egress proxy RUNNING, credential RUNNING

  EOF
  diff -u expected actual
  cat > expected-queries <<'EOF'
  show fencr-sbx.service --property=LoadState,ActiveState,MemoryCurrent
  show fencr-sbx-egress-proxy.service --property=LoadState,ActiveState
  show fencr-sbx-credentials.service --property=LoadState,ActiveState
  EOF
  diff -u expected-queries "$TEST_LOG"
  ${cli}/bin/fencr status sbx --full > /dev/null
  grep -Fx "status fencr-sbx.service fencr-sbx-egress-proxy.service fencr-sbx-credentials.service --no-pager" "$TEST_LOG"
  for state in failed inactive missing unavailable; do
    export TEST_STATE="$state"
    case "$state" in
      failed) health=FAILED ;;
      inactive) health=STOPPED ;;
      missing) health=MISSING ;;
      unavailable) health="unavailable: exit status: 1" ;;
    esac
    ${cli}/bin/fencr status sbx > actual
    grep -F "sbx  $health  10.30.1.2" actual
    grep -Fx "Services: egress proxy $health, credential $health" actual
  done
  touch "$out"
''
