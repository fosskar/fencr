self: pkgs:

# Work package 1 of the crosvm port: a systemd credential reaches a crosvm
# guest through crosvm's fw_cfg device. crosvm exposes no ACPI node for it and
# the nixos kernel's driver takes no command line parameter, so the guest gets
# the node qemu's own DSDT declares, as an SSDT.
let
  core = import ../modules/core.nix { inherit (pkgs) lib; };
  ssdt = core.fwCfgTable pkgs;
  secret = pkgs.writeText "fencr-crosvm-secret" "fencr crosvm secret\n";
in
import (pkgs.path + "/nixos/tests/make-test-python.nix")
  (_: {
    name = "fencr-crosvm-credentials";

    nodes.host = {
      imports = [ self.inputs.microvm.nixosModules.host ];

      virtualisation.qemu.options = [
        "-cpu"
        "kvm64,+svm,+vmx"
      ];
      virtualisation.diskSize = 4096;

      systemd.services."microvm@spike".serviceConfig.LoadCredential = "spike:${secret}";

      microvm.vms.spike = {
        autostart = true;
        config = {
          microvm = {
            hypervisor = "crosvm";
            vcpu = 1;
            mem = 512;
            crosvm.extraArgs = [
              "--acpi-table"
              "${ssdt}"
              "--fw-cfg"
              "name=opt/io.systemd.credentials/spike,path=/run/credentials/microvm@spike.service/spike"
              "--nested"
              "mode=off"
            ];
          };
          boot.initrd.kernelModules = [ "qemu_fw_cfg" ];
          systemd.services.spike = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig = {
              Type = "oneshot";
              ImportCredential = "spike";
            };
            script = ''
              echo "fencr-spike: $(cat "$CREDENTIALS_DIRECTORY/spike")" > /dev/console
              grep -c -wE 'svm|vmx' /proc/cpuinfo > /dev/console || echo "fencr-spike: no nested virt" > /dev/console
            '';
          };
          system.stateVersion = "25.11";
        };
      };

      system.stateVersion = "25.11";
    };

    testScript = ''
      host.wait_for_unit("microvm@spike.service", timeout=1200)
      host.wait_until_succeeds("journalctl -u microvm@spike --no-pager | grep -F 'fencr-spike: fencr crosvm secret'", timeout=300)
      host.succeed("journalctl -u microvm@spike --no-pager | grep -F 'fencr-spike: no nested virt'")
    '';

    meta.timeout = 1800;
  })
  {
    inherit pkgs;
    system = pkgs.stdenv.hostPlatform.system;
  }
