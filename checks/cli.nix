_self: pkgs:
let
  inherit (pkgs) lib;
  core = import ../modules/core { inherit lib; };
  instance = core.resolveInstance {
    name = "sbx";
    credentials.api = {
      upstream = "http://127.0.0.1:8764";
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
    printf 'LoadState=loaded\nActiveState=%s\nMemoryCurrent=1048576\nNAccepted=7\nNConnections=2\n' "$TEST_STATE"
  '';
  journalctl = pkgs.writeShellScriptBin "journalctl" "exit 0";
  nft = pkgs.writeShellScriptBin "nft" "exit 0";
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
    allowed  0 packets
    blocked  0 packets

  Connections:
    host -> guest: 127.0.0.1:33627 -> guest 33627  2 active (7 total)
    guest -> host: vsock 14000 -> host 14000  2 active (7 total)

  Domains: no requests observed
  Services: egress proxy RUNNING, credential RUNNING

  EOF
  diff -u expected actual
  cat > expected-queries <<'EOF'
  show fencr-sbx.service --property=LoadState,ActiveState,MemoryCurrent
  show sbx-forward-33627.socket --property=LoadState,ActiveState,NAccepted,NConnections
  show sbx-host-forward-14000.socket --property=LoadState,ActiveState,NAccepted,NConnections
  show sbx-egress-proxy.service --property=LoadState,ActiveState
  show sbx-credential-api.service --property=LoadState,ActiveState
  EOF
  diff -u expected-queries "$TEST_LOG"
  for state in failed inactive missing unavailable; do
    export TEST_STATE="$state"
    case "$state" in
      failed) health=FAILED ;;
      inactive) health=STOPPED ;;
      missing|unavailable) health=MISSING ;;
    esac
    ${cli}/bin/fencr status sbx > actual
    grep -F "sbx  $health  10.30.1.2" actual
    grep -Fx "Services: egress proxy $health, credential $health" actual
  done
  touch "$out"
''
