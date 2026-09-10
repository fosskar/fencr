{ core, ... }:
let
  inherit (core)
    hardened
    specialUseNetworks
    runDirOf
    stateDirOf
    ;
in
{

  # what firecracker's jailer builds with its chroot. ProtectSystem and
  # ProtectHome silently win over the tmpfs, so they are left out
  emptyRootOf =
    name:
    removeAttrs hardened [
      "ProtectHome"
      "ProtectSystem"
    ]
    // {
      TemporaryFileSystem = "/:ro";
      BindReadOnlyPaths = [ "/nix/store" ];
      BindPaths = [
        (runDirOf name)
        (stateDirOf name)
      ];
    };

  hardened = {
    CapabilityBoundingSet = "";
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    NoNewPrivileges = true;
    PrivateDevices = true;
    PrivateIPC = true;
    PrivateTmp = true;
    ProtectClock = true;
    ProtectControlGroups = true;
    ProtectHome = true;
    ProtectHostname = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    ProtectSystem = "strict";
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
      "~@resources"
    ];
    SystemCallArchitectures = "native";
    UMask = "0077";
  };

  # group kvm is what the credentials socket admits; the denied ranges keep
  # an upstream or an allowed name from resolving into the lan
  proxyHardening = hardened // {
    Restart = "always";
    RestartSec = 5;
    DynamicUser = true;
    Group = "kvm";
    IPAddressDeny = specialUseNetworks.v4 ++ specialUseNetworks.v6;
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
    ];
  };

  # never reached, even with an internet grant. the firewall enforces v4 on
  # the bridge and drops v6 wholesale; the proxy units enforce both
  specialUseNetworks = {
    v4 = [
      "0.0.0.0/8"
      "10.0.0.0/8"
      "100.64.0.0/10"
      "127.0.0.0/8"
      "169.254.0.0/16"
      "172.16.0.0/12"
      "192.0.0.0/24"
      "192.0.2.0/24"
      "192.168.0.0/16"
      "198.18.0.0/15"
      "198.51.100.0/24"
      "203.0.113.0/24"
      "224.0.0.0/4"
      "240.0.0.0/4"
    ];
    v6 = [
      "::/128"
      "::1/128"
      "::ffff:0:0/96"
      "64:ff9b::/96"
      "100::/64"
      "2001:db8::/32"
      "fc00::/7"
      "fe80::/10"
      "ff00::/8"
    ];
  };
}
