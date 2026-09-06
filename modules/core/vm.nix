{ core, ... }:
let
  inherit (core)
    stateDirOf
    stateImageOf
    userOf
    runDirOf
    vsockOf
    powerPort
    hardened
    ;
in
{

  # the hypervisor unit: the microvm.nix runner under the vm's own system
  # user in group kvm, so two vms' firecracker processes share no host
  # identity and the state image has a stable owner. AF_INET is for the tap
  # ioctls only. the umask lets group kvm, the relays, open the vsock
  # socket firecracker creates. the runner creates the state image on
  # first start; a larger stateSize grows it here and the guest grows the
  # filesystem
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
      serviceConfig =
        removeAttrs hardened [
          "PrivateDevices"
          "ProcSubset"
          "ProtectProc"
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
            printf 'CONNECT ${toString powerPort}\n' | ${pkgs.socat}/bin/socat -t 1 - UNIX-CONNECT:${vsockOf instance.name} || true
            while [ -d /proc/$MAINPID ]; do sleep 0.5; done
          '';
          TimeoutStopSec = 60;
          User = userOf instance.name;
          UMask = "0007";
          WorkingDirectory = runDir;
          Restart = "on-failure";
          RestartSec = 5;
          MemoryMax = instance.memoryMax;
          CPUQuota = instance.cpuQuota;
          CPUWeight = 20;
          ReadWritePaths = [
            runDir
            (stateDirOf instance.name)
          ];
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
