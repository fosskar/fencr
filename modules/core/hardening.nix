{ core, ... }:
let
  inherit (core) hardened;
in
{

  hardened = {
    CapabilityBoundingSet = "";
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    NoNewPrivileges = true;
    PrivateDevices = true;
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
    SystemCallArchitectures = "native";
    UMask = "0077";
  };

  # a relay handles whatever its peer sends; it gets a throwaway uid so a
  # bug in it shares nothing with the hypervisor process
  forwardHardening = hardened // {
    DynamicUser = true;
    SupplementaryGroups = [ "kvm" ];
    StandardInput = "socket";
    StandardError = "journal";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_UNIX"
    ];
  };

  proxyHardening = hardened // {
    Restart = "always";
    RestartSec = 5;
    DynamicUser = true;
    IPAddressAllow = "localhost";
    IPAddressDeny = "any";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_VSOCK"
    ];
  };

  # destinations a vm never reaches, even with open egress: private, link-local,
  # multicast and other special-use ranges. the firewall enforces the v4 list
  # on the bridge (v6 is dropped wholesale there); the egress proxy unit
  # enforces both on its own sockets
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
