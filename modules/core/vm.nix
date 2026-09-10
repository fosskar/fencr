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

  # the hypervisor unit: the microvm.nix runner under the vm's own system
  # user, so two vms' firecracker processes share no host identity and the
  # state image has a stable owner; group kvm is for /dev/kvm and the tap.
  # AF_INET is for the tap ioctls only. the runner creates the state image
  # on first start; a larger stateSize grows it here and the guest grows
  # the filesystem. the process sees the empty root: code that escapes
  # the vm into it finds no host file to read
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
      # firecracker installs its own per-thread allowlist, tighter than
      # @system-service and including mincore, which that group lacks
      serviceConfig =
        removeAttrs (emptyRootOf instance.name) [
          "PrivateDevices"
          "SystemCallFilter"
        ]
        // {
          # firecracker leaves its vsock socket behind and refuses to bind
          # over it
          ExecStartPre = pkgs.writeShellScript "fencr-${instance.name}-prepare" ''
            set -eu
            ${pkgs.coreutils}/bin/rm -f ${vsockOf instance.name}
            if [ -e ${image} ] && [ "$(${pkgs.coreutils}/bin/stat -c %s ${image})" -lt $((${toString instance.stateSize} * 1048576)) ]; then
              ${pkgs.coreutils}/bin/truncate -s ${toString instance.stateSize}M ${image}
            fi
          '';
          ExecStart = "${runner}/bin/microvm-run";
          # press the power button, then wait for firecracker to exit so the
          # guest gets to unmount its state; a guest that never answers is
          # killed at the stop timeout
          ExecStop = pkgs.writeShellScript "fencr-${instance.name}-stop" ''
            printf 'CONNECT ${toString powerPort}\n' | ${pkgs.socat}/bin/socat -t 1 - UNIX-CONNECT:${vsockOf instance.name}
            while [ -d /proc/$MAINPID ]; do sleep 0.5; done
          '';
          TimeoutStopSec = 60;
          # after a clean stop the image is quiescent: copy it, as the
          # vm's user in this same root. "-": a filesystem without
          # reflinks must not fail the unit
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
