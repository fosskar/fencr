{ lib, core, ... }:
let
  inherit (core)
    stateImageOf
    userOf
    runDirOf
    vsockOf
    powerPort
    emptyRootOf
    checkpointScript
    ;
in
{

  # the runner under a system user of its own, so two vms share no host
  # identity and the state image has an owner outliving the unit. group kvm
  # is for /dev/kvm and the tap, AF_INET for the tap ioctls
  vmService =
    pkgs: instance: runner:
    let
      runDir = runDirOf instance.name;
      image = stateImageOf instance.name;
    in
    {
      description = "fencr sandbox ${instance.name}";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      # firecracker's own per-thread allowlist is tighter than
      # @system-service and includes mincore, which that group lacks
      serviceConfig =
        removeAttrs (emptyRootOf instance.name) [
          "PrivateDevices"
          "SystemCallFilter"
        ]
        // {
          # firecracker leaves its vsock socket behind and refuses to bind over it.
          # the guest grows the filesystem after a larger stateSize grows the image
          ExecStartPre = pkgs.writeShellScript "fencr-${instance.name}-prepare" ''
            set -eu
            ${pkgs.coreutils}/bin/rm -f ${vsockOf instance.name}
            if [ -e ${image} ] && [ "$(${pkgs.coreutils}/bin/stat -c %s ${image})" -lt $((${toString instance.stateSize} * 1048576)) ]; then
              ${pkgs.coreutils}/bin/truncate -s ${toString instance.stateSize}M ${image}
            fi
          '';
          ExecStart = "${runner}/bin/microvm-run";
          # wait for the exit so the guest unmounts its state; one that never
          # answers is killed at the stop timeout
          ExecStop = pkgs.writeShellScript "fencr-${instance.name}-stop" ''
            printf 'CONNECT ${toString powerPort}\n' | ${pkgs.socat}/bin/socat -t 1 - UNIX-CONNECT:${vsockOf instance.name}
            while [ -d /proc/$MAINPID ]; do sleep 0.5; done
          '';
          TimeoutStopSec = 60;
          # "-": a filesystem without reflinks must not fail the unit
          ExecStopPost = lib.optional instance.checkpoints.onStop "-${checkpointScript pkgs instance} stop";
          User = userOf instance.name;
          WorkingDirectory = runDir;
          Restart = "on-failure";
          RestartSec = 5;
          MemoryMax = instance.memoryMax;
          CPUQuota = instance.cpuQuota;
          CPUWeight = 20;
          DevicePolicy = "closed";
          DeviceAllow = [
            "/dev/kvm rw"
            "/dev/net/tun rw"
          ];
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_INET"
          ];
          IPAddressDeny = "any";
        };
    };
}
