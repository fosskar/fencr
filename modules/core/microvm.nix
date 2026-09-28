{ lib, core, ... }:
let
  inherit (core)
    stateImageOf
    userOf
    runDirOf
    vsockOf
    powerPort
    emptyRootOf
    checkpointCommand
    unitsOf
    ;
in
{

  # the runner under a system user of its own, so two sandboxes share no host
  # identity and the state image has an owner outliving the unit. group kvm
  # is for /dev/kvm, AF_INET for the tap ioctls
  microvmService =
    pkgs: cli: instance: runner:
    let
      runDir = runDirOf instance.name;
      image = stateImageOf instance.name;
    in
    {
      description = "fencr sandbox ${instance.name}";
      wantedBy = [ "multi-user.target" ];
      # the sandbox's tables are what confine the guest: a ruleset that failed to
      # load, or was stopped, must not leave the guest running unconfined
      requires = [ "nftables.service" ];
      # the relays serve one fetch per boot and then close; every start of
      # the guest, restarts included, pulls them in again
      wants =
        lib.optional (instance.secrets != { }) "${(unitsOf instance.name).secrets}.socket"
        ++ lib.optional (instance.credentials != [ ]) "${(unitsOf instance.name).trust}.socket";
      after = [
        "network.target"
        "nftables.service"
      ];
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
          # firecracker reopens its log path; journald's socket cannot be reopened as a file
          ExecStart = pkgs.writeShellScript "fencr-${instance.name}-run" ''
            exec ${runner}/bin/microvm-run 2> >(exec ${pkgs.coreutils}/bin/cat >&2)
          '';
          StandardOutput = "null";
          StandardError = "journal";
          # wait for the exit so the guest unmounts its state; one that never
          # answers is killed at the stop timeout
          ExecStop = pkgs.writeShellScript "fencr-${instance.name}-stop" ''
            printf 'CONNECT ${toString powerPort}\n' | ${pkgs.socat}/bin/socat -t 1 - UNIX-CONNECT:${vsockOf instance.name}
            while [ -d /proc/$MAINPID ]; do sleep 0.5; done
          '';
          TimeoutStopSec = 60;
          # "-": a filesystem without reflinks must not fail the unit
          ExecStopPost = lib.optional instance.checkpoints.onStop "-${checkpointCommand cli instance} stop";
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
