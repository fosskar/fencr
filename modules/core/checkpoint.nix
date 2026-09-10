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
  # firecracker's api socket, in the run directory only the vm's user
  # enters; a checkpoint pauses the vm through it
  apiSocketOf = name: "${runDirOf name}/api.sock";

  # checkpoints are copies of the state image beside it, named
  # "<kind>-<utc stamp>" for the automatic kinds and as given for manual
  # ones; the vm's user owns them like the image
  checkpointDirOf = name: "${stateDirOf name}/checkpoints";

  # the copy: a reflink, so it is instant and shares blocks with the image
  # until either side writes. the clone is one atomic operation on the
  # file, so a running vm's copy is a crash-consistent image of what
  # reached the host disk, which Writeback keeps complete. the vm is not
  # paused around it: firecracker 1.16 leaves host-to-guest vsock dead
  # after a bare pause/resume (fixed in 1.17, #6100), which would take
  # the power button with it. on a filesystem without reflinks a running
  # copy would take minutes of racing the guest, so it is refused there;
  # on the stop path the guest has unmounted and a plain sparse copy
  # stands in. the automatic kinds are pruned to `keep` each, manual
  # names are never touched
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

      # the timer has nothing to add for a stopped vm; the api answers
      # only while firecracker runs
      if [ "$label" = timer ] && ! curl --silent --fail --unix-socket "$socket" http://localhost/ > /dev/null; then
        echo "fencr: no timer checkpoint: the vm is not running" >&2
        exit 0
      fi

      mkdir -p -m 0700 "$dir"
      if [ -e "$dir/$name.img" ]; then
        echo "fencr: checkpoint \"$name\" exists" >&2
        exit 1
      fi
      # the runner makes the image nodatacow on btrfs, and btrfs clones
      # only between files with the same attribute: give the copy the
      # image's before cloning into it; elsewhere chattr has nothing to do
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
      echo "fencr: checkpoint $name"
      for kind in stop timer; do
        find "$dir" -maxdepth 1 -name "$kind-*.img" | sort | head -n -${toString instance.checkpoints.keep} | xargs -r rm --
      done
    '';

  # the unit set behind checkpoints: a template the timer and the command
  # start with the name as instance, and the timer when an interval is
  # set. it runs as the vm's user in the vm unit's own empty root, with
  # the api socket as its only reach
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
