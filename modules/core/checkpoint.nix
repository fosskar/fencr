{ lib, core, ... }:
let
  inherit (core)
    stateDirOf
    runDirOf
    userOf
    unitsOf
    emptyRootOf
    checkpointCommand
    ;
in
{
  apiSocketOf = name: "${runDirOf name}/api.sock";

  checkpointDirOf = name: "${stateDirOf name}/checkpoints";

  # the reflink is atomic on the file, so a running sandbox's copy is
  # crash-consistent without pausing it, which firecracker 1.16 cannot
  # survive: a bare pause/resume kills host-to-guest vsock and with it the
  # power button (fixed in 1.17, #6100). without reflinks the copy would
  # race the guest for minutes, so only the stop path falls back to one.
  # see docs/decisions/checkpoints.md
  checkpointCommand = cli: instance: "${cli}/bin/fencr write-checkpoint ${instance.name}";

  # a template the timer and the command start with the name as instance
  checkpointUnits =
    cli: instance:
    let
      units = unitsOf instance.name;
    in
    {
      services."${units.checkpoint}@" = {
        description = "checkpoint %i of fencr sandbox ${instance.name}";
        serviceConfig = emptyRootOf instance.name // {
          Type = "oneshot";
          User = userOf instance.name;
          ExecStart = "${checkpointCommand cli instance} %i";
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
