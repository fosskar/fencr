{ core, ... }:
let
  inherit (core) hardened specialUseNetworks;
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

  # the proxies: a throwaway uid in group kvm, which is what the credentials
  # socket admits; every special-use range denied so an upstream or an
  # allowed name cannot resolve into the lan. each allows its own addresses
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

  # destinations a vm never reaches, even with open egress: private, link-local,
  # multicast and other special-use ranges. the firewall enforces the v4 list
  # on the bridge (v6 is dropped wholesale there); the proxy units enforce
  # both on their own sockets
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
