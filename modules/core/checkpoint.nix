{ lib, core, ... }:
let
  inherit (core)
    stateDirOf
    stateImageOf
    runDirOf
    apiSocketOf
    userOf
    unitsOf
    emptyRootOf
    checkpointDirOf
    checkpointScript
    ;
in
{
  apiSocketOf = name: "${runDirOf name}/api.sock";

  checkpointDirOf = name: "${stateDirOf name}/checkpoints";

  # the reflink is atomic on the file, so a running vm's copy is
  # crash-consistent without pausing it, which firecracker 1.16 cannot
  # survive: a bare pause/resume kills host-to-guest vsock and with it the
  # power button (fixed in 1.17, #6100). without reflinks the copy would
  # race the guest for minutes, so only the stop path falls back to one.
  # see docs/decisions/checkpoints.md
  checkpointScript =
    pkgs: instance:
    pkgs.writeShellScript "fencr-${instance.name}-checkpoint" ''
      set -eu
      PATH=${
        lib.makeBinPath [
          pkgs.coreutils
          pkgs.curl
          pkgs.e2fsprogs
          pkgs.findutils
        ]
      }
      label=$1
      image=${stateImageOf instance.name}
      dir=${checkpointDirOf instance.name}
      socket=${apiSocketOf instance.name}

      case "$label" in
        stop)
          if [ "''${SERVICE_RESULT:-success}" != success ]; then
            echo "fencr: no stop checkpoint: the vm ended with $SERVICE_RESULT" >&2
            exit 0
          fi
          name="stop-$(date -u +%Y%m%dT%H%M%S)"
          ;;
        timer | manual)
          name="$label-$(date -u +%Y%m%dT%H%M%S)"
          ;;
        stop-* | timer-* | manual-*)
          echo "fencr: \"$label\" is reserved for automatic checkpoints" >&2
          exit 1
          ;;
        *)
          if [[ ! $label =~ ^[A-Za-z0-9_.-]+$ ]]; then
            echo "fencr: \"$label\" is not a checkpoint name (letters, digits, \"_.-\")" >&2
            exit 1
          fi
          name=$label
          ;;
      esac

      # the api answers only while firecracker runs
      if [ "$label" = timer ] && ! curl --silent --fail --unix-socket "$socket" http://localhost/ > /dev/null; then
        echo "fencr: no timer checkpoint: the vm is not running" >&2
        exit 0
      fi

      mkdir -p -m 0700 "$dir"
      if [ -e "$dir/$name.img" ]; then
        echo "fencr: checkpoint \"$name\" exists" >&2
        exit 1
      fi
      # btrfs clones only between files whose nodatacow attribute matches,
      # and the runner sets it on the image
      rm -f "$dir/$name.img.tmp"
      touch "$dir/$name.img.tmp"
      chmod 0600 "$dir/$name.img.tmp"
      if [ "$(stat -f -c %T "$image")" = btrfs ]; then
        case "$(lsattr -d "$image" | cut -d' ' -f1)" in
          *C*) chattr +C "$dir/$name.img.tmp" ;;
        esac
      fi
      if [ "$label" = stop ]; then
        cp --reflink=auto --sparse=always "$image" "$dir/$name.img.tmp"
      elif ! cp --reflink=always "$image" "$dir/$name.img.tmp"; then
        echo "fencr: no checkpoint of a running vm without reflinks on $(stat -f -c %T "$image"); stop checkpoints still copy" >&2
        exit 1
      fi
      mv "$dir/$name.img.tmp" "$dir/$name.img"
      # a clone that has not reached the disk is lost with the host, and on
      # zfs its blocks are unaccounted until the transaction group commits
      sync -f "$dir/$name.img"
      echo "fencr: checkpoint $name"
      for kind in stop timer; do
        find "$dir" -maxdepth 1 -name "$kind-*.img" | sort | head -n -${toString instance.checkpoints.keep} | xargs -r rm --
      done
    '';

  # a template the timer and the command start with the name as instance
  checkpointUnits =
    pkgs: instance:
    let
      units = unitsOf instance.name;
      script = checkpointScript pkgs instance;
    in
    {
      services."${units.checkpoint}@" = {
        description = "checkpoint %i of fencr sandbox ${instance.name}";
        serviceConfig = emptyRootOf instance.name // {
          Type = "oneshot";
          User = userOf instance.name;
          ExecStart = "${script} %i";
          RestrictAddressFamilies = [ "AF_UNIX" ];
          IPAddressDeny = "any";
        };
      };
      timers = lib.optionalAttrs (instance.checkpoints.interval != null) {
        ${units.checkpoint} = {
          description = "periodic checkpoints of fencr sandbox ${instance.name}";
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnCalendar = instance.checkpoints.interval;
            Unit = "${units.checkpoint}@timer.service";
          };
        };
      };
    };
}
