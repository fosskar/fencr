self: system:

# Evaluation smoke test: a machine with one instance exercising forwards,
# host forwards and the credential broker.
{
  imports = [ self.nixosModules.fencr ];

  boot.loader.grub.devices = [ "/dev/sda" ];
  fileSystems."/" = {
    device = "/dev/sda1";
    fsType = "ext4";
  };

  fencr.vms.sbx = {
    id = 0;
    vcpu = 2;
    mem = 1024;
    dns = "9.9.9.9";
    hostPorts = [ 443 ];
    allowedTCPDestinations = [
      {
        address = "192.168.1.50";
        port = 8123;
      }
    ];
    forwards = [
      {
        listenPort = 8080;
        guestPort = 8080;
      }
    ];
    hostForwards = [
      {
        vsockPort = 18764;
        targetPort = 8764;
        broker = {
          port = 28764;
          secretFile = "/run/secrets/broker-token";
        };
      }
    ];
  };

  system.stateVersion = "25.11";

  nixpkgs.hostPlatform = system;
}
