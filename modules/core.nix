# the shared core of both frontends (nixos module and flakelet): instance
# derivation, firewall rule text, forward transports, the credential broker
# and the guest system. both frontends must consume these builders so the
# seal semantics cannot drift between them.
{ lib }:
rec {
  tapOf = name: "tap-${name}";
  bridgeOf = name: "br-${name}";
  macOf = cfg: "02:00:00:00:20:0${toString (cfg.id + 1)}";
  cidOf = cfg: 3 + cfg.id;
  hostIpOf = cfg: "10.30.${toString (cfg.id + 1)}.1";
  ipOf = cfg: "10.30.${toString (cfg.id + 1)}.2";

  secretsDirOf = name: "/var/lib/fencr/${name}/secrets";
  stateDirOf = name: "/var/lib/fencr-vms/${name}";

  # "<ipv4[/prefix]>:<port>" sugar for destination entries. hostnames need
  # runtime resolution and stay unsupported until name-based egress exists.
  parseDestination =
    value:
    if builtins.isAttrs value then
      value
    else
      let
        matched = builtins.match "([0-9./]+):([0-9]+)" value;
      in
      if matched == null then
        throw "fencr: destination \"${value}\" is not <ipv4[/prefix]>:<port>; hostnames are not supported yet"
      else
        {
          address = builtins.elemAt matched 0;
          port = lib.toInt (builtins.elemAt matched 1);
        };

  # expose sugar: "33627" listens on host loopback 33627 and relays to guest
  # loopback 33627; "<listenAddress>:<listenPort>:<guestPort>" spells it out
  parseExpose =
    value:
    if builtins.isAttrs value then
      value
    else
      let
        short = builtins.match "([0-9]+)" value;
        long = builtins.match "([0-9.]+):([0-9]+):([0-9]+)" value;
      in
      if short != null then
        rec {
          listenAddress = "127.0.0.1";
          listenPort = lib.toInt (builtins.elemAt short 0);
          guestPort = listenPort;
        }
      else if long != null then
        {
          listenAddress = builtins.elemAt long 0;
          listenPort = lib.toInt (builtins.elemAt long 1);
          guestPort = lib.toInt (builtins.elemAt long 2);
        }
      else
        throw "fencr: expose entry \"${value}\" is neither <port> nor <listenAddress>:<listenPort>:<guestPort>";

  vsockForwardBin =
    pkgs:
    pkgs.writers.writeRustBin "fencr-vsock-forward" {
      rustcArgs = [
        "-O"
        "--edition"
        "2021"
      ];
    } ./vsock-forward.rs;

  # per-connection forward helpers; the frontend adds the process identity
  # (User/Group on nixos, DynamicUser under flakelet)
  forwardHardening = {
    StandardInput = "socket";
    StandardError = "journal";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_VSOCK"
    ];
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
    ProtectSystem = "strict";
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
  };

  proxyHardening = {
    Restart = "always";
    RestartSec = 5;
    DynamicUser = true;
    CapabilityBoundingSet = "";
    IPAddressAllow = "localhost";
    IPAddressDeny = "any";
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
    ProtectSystem = "strict";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_VSOCK"
    ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
  };

  # host to guest: accepted tcp connection spliced to the guest's vsock port
  forwardCommand =
    pkgs: cfg: forward:
    "${pkgs.socat}/bin/socat STDIO VSOCK-CONNECT:${toString (cidOf cfg)}:${toString forward.guestPort}";

  # guest to host: accepted vsock connection, cid-checked, spliced to a host
  # loopback port. a brokered forward lands on the broker, not the target.
  hostForwardCommand =
    pkgs: cfg: forward:
    let
      target = if forward.broker != null then forward.broker.port else forward.targetPort;
    in
    "${vsockForwardBin pkgs}/bin/fencr-vsock-forward ${toString (cidOf cfg)} ${toString target}";

  # domain-allowlist egress: the guest's only way out is a host-side
  # tinyproxy reached over vsock; it enforces the allowlist on the CONNECT
  # hostname, so https needs no interception. the port doubles as the
  # guest's loopback proxy port and the vsock port.
  proxyPortOf = cfg: 13128 + cfg.id;

  # a pattern is a hostname, optionally with a leading "*." label. anything
  # else is rejected: "*github.com" also matches evilgithub.com, and stray
  # fnmatch metacharacters widen the allowlist silently.
  domainPatternError =
    pattern:
    if builtins.match "(\\*\\.)?([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+" pattern != null then
      null
    else if lib.hasPrefix "*" pattern && !lib.hasPrefix "*." pattern then
      "\"${pattern}\": a wildcard must be its own label (\"*.example.com\"); \"*example.com\" also matches evilexample.com"
    else
      "\"${pattern}\": not a hostname pattern; expected \"example.com\" or \"*.example.com\"";

  domainPatternErrors = domains: lib.filter (e: e != null) (map domainPatternError domains);

  proxyFilterFile =
    pkgs: domains:
    pkgs.writeText "fencr-egress-domains" (lib.concatMapStrings (domain: "${domain}\n") domains);

  tinyproxyConfig =
    pkgs: port: domains:
    pkgs.writeText "fencr-tinyproxy.conf" ''
      Port ${toString port}
      Listen 127.0.0.1
      Allow 127.0.0.1
      Timeout 600
      MaxClients 32
      LogLevel Warning
      DisableViaHeader Yes
      FilterType fnmatch
      FilterDefaultDeny Yes
      Filter "${proxyFilterFile pkgs domains}"
    '';

  egressProxyServiceConfig = pkgs: port: domains: {
    ExecStart = "${pkgs.tinyproxy}/bin/tinyproxy -d -c ${tinyproxyConfig pkgs port domains}";
    Restart = "always";
    RestartSec = 5;
    DynamicUser = true;
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
    ProtectSystem = "strict";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
    ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
  };

  # the credential broker: the guest talks plain http through the vsock
  # forward; this proxy holds the secret and injects the header on the host
  # side, so the value never exists inside the vm.
  brokerCaddyfile =
    pkgs: broker: targetPort:
    pkgs.writeText "fencr-broker.caddyfile" ''
      {
        admin off
        auto_https off
      }
      http://127.0.0.1:${toString broker.port} {
        reverse_proxy 127.0.0.1:${toString targetPort} {
          header_up ${broker.header} {$FENCR_BROKER_SECRET}
        }
      }
    '';

  brokerExec =
    pkgs: broker: targetPort:
    pkgs.writeShellScript "fencr-broker" ''
      FENCR_BROKER_SECRET="$(cat "$CREDENTIALS_DIRECTORY/secret")"
      export FENCR_BROKER_SECRET
      exec ${pkgs.caddy}/bin/caddy run --config ${
        brokerCaddyfile pkgs broker targetPort
      } --adapter caddyfile
    '';

  brokerServiceConfig =
    pkgs: broker: targetPort:
    {
      ExecStart = "${brokerExec pkgs broker targetPort}";
      LoadCredential = "secret:${broker.secretFile}";
      Environment = [
        "XDG_DATA_HOME=/tmp"
        "XDG_CONFIG_HOME=/tmp"
      ];
    }
    // proxyHardening;

  # forward-chain fragment sealing a bridge. egress "open": dns and declared
  # pinholes plus the internet, every other private range dropped. egress
  # "closed": nothing but the declared pinholes, dns included in nothing.
  # replies to whatever was allowed flow back either way.
  forwardFilterFragment =
    cfg:
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
    ''
    + lib.optionalString (cfg.egress == "open") ''
      iifname "${cfg.bridge}" ip daddr ${cfg.dns} udp dport 53 accept
      iifname "${cfg.bridge}" ip daddr ${cfg.dns} tcp dport 53 accept
    ''
    + lib.concatMapStringsSep "\n" (
      destination:
      ''iifname "${cfg.bridge}" ip daddr ${destination.address} tcp dport ${toString destination.port} accept''
    ) cfg.allowedTCPDestinations
    + "\n"
    + (
      if cfg.egress == "open" then
        ''
          iifname "${cfg.bridge}" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
          iifname "${cfg.bridge}" accept
        ''
      else
        ''
          iifname "${cfg.bridge}" drop
        ''
    )
    + ''
      oifname "${cfg.bridge}" ct state established,related accept
    '';

  natRuleFragment = cfg: ''
    ip saddr ${cfg.ip} oifname != "${cfg.bridge}" masquerade
  '';

  # input-chain fragment sealing the vms' host access to the declared ports
  sealInputFragment =
    cfg: ports:
    ''
      iifname "${cfg.bridge}" ct state established,related accept
    ''
    + lib.optionalString (ports != [ ]) ''
      iifname "${cfg.bridge}" tcp dport { ${lib.concatMapStringsSep ", " toString ports} } accept
    ''
    + ''
      iifname "${cfg.bridge}" counter drop
    '';

  # the environment itself: hardware shape, network posture, and a /var/lib
  # that survives reboots so whatever is installed inside keeps its state.
  guestBase =
    {
      agentSandbox,
      lib,
      pkgs,
      ...
    }:
    {
      microvm = {
        hypervisor = "qemu";
        inherit (agentSandbox) vcpu mem;
        balloon = true;
        deflateOnOOM = true;
        vsock.cid = agentSandbox.vsockCid;

        interfaces = [
          {
            type = "tap";
            id = agentSandbox.tap;
            inherit (agentSandbox) mac;
          }
        ];

        shares = [
          {
            source = "/nix/store";
            mountPoint = "/nix/.ro-store";
            tag = "ro-store";
            proto = "virtiofs";
          }
        ]
        ++ lib.optional agentSandbox.hasSecrets {
          source = secretsDirOf agentSandbox.name;
          mountPoint = "/run/agent-secrets";
          tag = "secrets";
          proto = "virtiofs";
        }
        ++ [
          {
            # every agent keeps its state under /var/lib, so share the whole
            # tree rather than making each one declare a directory
            source = stateDirOf agentSandbox.name;
            mountPoint = "/var/lib";
            tag = "state";
            proto = "virtiofs";
          }
        ];
      };

      # the host connects over vsock, so every forwarded port needs a listener
      # on the guest side of it. the relayed service itself only binds
      # loopback. host forwards get the mirror image: a loopback listener
      # relayed to the host's vsock cid.
      systemd.services = lib.listToAttrs (
        map (forward: {
          name = "fencr-vsock-proxy-${toString forward.guestPort}";
          value = {
            description = "vsock proxy for port ${toString forward.guestPort}";
            wantedBy = [ "multi-user.target" ];
            serviceConfig = proxyHardening // {
              ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString forward.guestPort},fork TCP:127.0.0.1:${toString forward.guestPort}";
            };
          };
        }) agentSandbox.expose
        ++ map (forward: {
          name = "fencr-vsock-host-proxy-${toString forward.targetPort}";
          value = {
            description = "host vsock proxy for port ${toString forward.targetPort}";
            wantedBy = [ "multi-user.target" ];
            serviceConfig = proxyHardening // {
              ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:${toString forward.targetPort},bind=127.0.0.1,fork VSOCK-CONNECT:2:${toString forward.vsockPort}";
            };
          };
        }) agentSandbox.hostForwards
      );

      networking = {
        useDHCP = false;
        useNetworkd = true;
        firewall.enable = true;
      };

      # virtio gives unpredictable enp0sN names, so match the mac we assigned.
      # v4 only: no RA-assigned v6 for the host's v4 forward rules to miss
      systemd.network.networks."10-lan" = {
        matchConfig.MACAddress = agentSandbox.mac;
        networkConfig = {
          Address = "${agentSandbox.ip}/${toString agentSandbox.prefixLength}";
          Gateway = agentSandbox.hostIp;
          DNS = agentSandbox.dns;
          IPv6AcceptRA = false;
          LinkLocalAddressing = "ipv4";
        };
      };

      # /etc is rebuilt on every boot, so keep the host key on the state
      # volume; otherwise the host's known_hosts breaks each time
      systemd.tmpfiles.rules = [ "d /var/lib/ssh 0700 root root - -" ];

      services.openssh = {
        enable = true;
        settings.PasswordAuthentication = false;
        hostKeys = [
          {
            path = "/var/lib/ssh/ssh_host_ed25519_key";
            type = "ed25519";
          }
        ];
      };

      users.users.root.openssh.authorizedKeys.keys = lib.optional (
        agentSandbox.adminPublicKey != null
      ) agentSandbox.adminPublicKey;

      # with a domain allowlist the proxy is the only road out, so every
      # process learns about it; tools that ignore the variables just hit
      # the closed firewall
      environment.variables = lib.mkIf (agentSandbox.proxy != null) (
        let
          url = "http://127.0.0.1:${toString agentSandbox.proxy.port}";
        in
        {
          http_proxy = url;
          https_proxy = url;
          HTTP_PROXY = url;
          HTTPS_PROXY = url;
          no_proxy = "127.0.0.1,localhost";
          NO_PROXY = "127.0.0.1,localhost";
        }
      );
      systemd.globalEnvironment = lib.mkIf (agentSandbox.proxy != null) (
        let
          url = "http://127.0.0.1:${toString agentSandbox.proxy.port}";
        in
        {
          HTTP_PROXY = url;
          HTTPS_PROXY = url;
          NO_PROXY = "127.0.0.1,localhost";
        }
      );

      # fetch tools for whatever runs inside; language runtimes ship with the
      # agent that needs them
      environment.systemPackages = [
        pkgs.curl
        pkgs.git
      ];

      system.stateVersion = lib.versions.majorMinor lib.version;
    };
}
