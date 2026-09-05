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
    ProtectSystem = "strict";
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
  };

  forwardHardening = hardened // {
    StandardInput = "socket";
    StandardError = "journal";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_VSOCK"
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

  proxyOf = cfg: if cfg.allowedDomains == [ ] then null else { port = proxyPortOf cfg; };

  hostForwardsOf =
    cfg:
    cfg.hostForwards
    ++ lib.optional (proxyOf cfg != null) {
      vsockPort = (proxyOf cfg).port;
      targetPort = (proxyOf cfg).port;
      broker = null;
    };

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
      LogLevel Connect
      DisableViaHeader Yes
      FilterType fnmatch
      FilterDefaultDeny Yes
      Filter "${proxyFilterFile pkgs domains}"
      ConnectPort 443
    '';

  egressProxyServiceConfig =
    pkgs: port: domains:
    hardened
    // {
      ExecStart = "${pkgs.tinyproxy}/bin/tinyproxy -d -c ${tinyproxyConfig pkgs port domains}";
      Restart = "always";
      RestartSec = 5;
      DynamicUser = true;
      IPAddressAllow = [
        "0.0.0.0/0"
        "::/0"
        "127.0.0.1/32"
      ];
      IPAddressDeny = specialUseNetworks.v4 ++ specialUseNetworks.v6;
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
      ];
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
          header_up ${broker.header} "{$FENCR_BROKER_SECRET}"
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

  resolveInstance =
    {
      name,
      options,
      sshKeys,
    }:
    let
      proxy = proxyOf options;
      expose = map parseExpose options.expose;
      declaredHostForwards = options.hostForwards;
      hostForwards = hostForwardsOf options;
      bridge = options.bridge or (bridgeOf name);
      hostIp = options.hostIp or (hostIpOf options);
      ip = options.ip or (ipOf options);
      prefixLength = options.prefixLength or 24;
      tap = tapOf name;
      mac = macOf options;
      vsockCid = cidOf options;
      allowedTCPDestinations = map parseDestination options.allowedTCPDestinations;
      invalidSecretNames = lib.filter (secretName: builtins.match "[A-Za-z0-9_.-]+" secretName == null) (
        lib.attrNames options.secrets
      );
      errors =
        lib.optional (options.id < 0 || options.id > 8) "${name}: id must be between 0 and 8"
        ++ map (
          secretName:
          "${name}: secret name \"${secretName}\" contains characters unsupported by systemd credentials"
        ) invalidSecretNames
        ++ lib.optional (
          lib.stringLength tap > 15
        ) "vm name \"${name}\" is too long: \"${tap}\" exceeds IFNAMSIZ"
        ++ lib.optional (lib.stringLength bridge > 15) "${name}: bridge name \"${bridge}\" exceeds IFNAMSIZ"
        ++ lib.optional (
          options.allowedDomains != [ ] && options.egress != "closed"
        ) "${name}: allowedDomains requires egress = \"closed\""
        ++ map (error: "${name}: invalid allowedDomains ${error}") (
          domainPatternErrors options.allowedDomains
        );
      guest = {
        inherit
          name
          sshKeys
          tap
          mac
          vsockCid
          bridge
          ip
          hostIp
          prefixLength
          proxy
          hostForwards
          ;
        inherit (options) vcpu mem dns;
        inherit expose;
        kind = "microvm";
        bindAddress = "127.0.0.1";
        secretNames = lib.attrNames options.secrets;
      };
    in
    {
      inherit
        name
        bridge
        tap
        mac
        ip
        hostIp
        prefixLength
        proxy
        expose
        hostForwards
        declaredHostForwards
        allowedTCPDestinations
        errors
        guest
        ;
      inherit (options)
        id
        vcpu
        mem
        dns
        egress
        allowedDomains
        hostPorts
        ;
      cid = vsockCid;
      brokeredForwards = lib.filter (forward: forward.broker != null) declaredHostForwards;
      forwardEndpoints =
        map (forward: "tcp:${forward.listenAddress}:${toString forward.listenPort}") expose
        ++ map (forward: "vsock:${toString forward.vsockPort}") hostForwards
        ++ map (forward: "tcp:127.0.0.1:${toString forward.broker.port}") (
          lib.filter (forward: forward.broker != null) declaredHostForwards
        );
    };

  fleetErrors =
    instances:
    let
      values = lib.attrValues instances;
      duplicate = values: lib.length values != lib.length (lib.unique values);
    in
    lib.optional (duplicate (map (instance: instance.id) values)) "instance ids must be unique"
    ++ lib.optional (duplicate (
      lib.concatMap (instance: instance.forwardEndpoints) values
    )) "host listen endpoints must be unique across instances";

  hostUnits =
    pkgs: instance: frontend:
    let
      inherit (frontend) forwardName;
      inherit (frontend) hostForwardName;
      inherit (frontend) proxyName;
      inherit (frontend) brokerName;
      forwardServices = map (forward: {
        name = "${forwardName forward}@";
        value = {
          description = "forward to ${instance.name} guest port ${toString forward.guestPort}";
          after = [ frontend.vmUnit ];
          requires = [ frontend.vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          serviceConfig =
            forwardHardening
            // frontend.identity
            // {
              ExecStart = forwardCommand pkgs instance forward;
            };
        };
      }) instance.expose;
      hostForwardServices = map (forward: {
        name = "${hostForwardName forward}@";
        value = {
          description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
          after = [ frontend.vmUnit ];
          requires = [ frontend.vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          serviceConfig =
            forwardHardening
            // frontend.identity
            // {
              ExecStart = hostForwardCommand pkgs instance forward;
            };
        };
      }) instance.hostForwards;
      brokerServices = map (forward: {
        name = brokerName forward;
        value = {
          description = "credential broker for ${instance.name} vsock port ${toString forward.vsockPort}";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = brokerServiceConfig pkgs forward.broker forward.targetPort;
        };
      }) instance.brokeredForwards;
      forwardSockets = map (forward: {
        name = forwardName forward;
        value = {
          description = "forward to ${instance.name} guest port ${toString forward.guestPort}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = "${forward.listenAddress}:${toString forward.listenPort}";
            Accept = true;
            MaxConnections = 64;
          };
        };
      }) instance.expose;
      hostForwardSockets = map (forward: {
        name = hostForwardName forward;
        value = {
          description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = "vsock::${toString forward.vsockPort}";
            Accept = true;
            MaxConnections = 64;
            TriggerLimitIntervalSec = 0;
          };
        };
      }) instance.hostForwards;
    in
    {
      services =
        lib.listToAttrs (forwardServices ++ hostForwardServices ++ brokerServices)
        // lib.optionalAttrs (instance.proxy != null) {
          ${proxyName} = {
            description = "domain-allowlist egress proxy for ${instance.name}";
            wantedBy = [ "multi-user.target" ];
            serviceConfig = egressProxyServiceConfig pkgs instance.proxy.port instance.allowedDomains;
          };
        };
      sockets = lib.listToAttrs (forwardSockets ++ hostForwardSockets);
      unitNames = {
        vm = frontend.vmUnit;
        sockets =
          map (forward: {
            unit = "${forwardName forward}.socket";
            label = "in  ${forward.listenAddress}:${toString forward.listenPort} -> guest ${toString forward.guestPort}";
          }) instance.expose
          ++ map (forward: {
            unit = "${hostForwardName forward}.socket";
            label = "out vsock ${toString forward.vsockPort} -> host ${toString forward.targetPort}";
          }) instance.hostForwards;
        proxy = lib.optional (instance.proxy != null) "${proxyName}.service";
        brokers = map (forward: {
          unit = "${brokerName forward}.service";
          label = "broker 127.0.0.1:${toString forward.broker.port} -> ${toString forward.targetPort}";
        }) instance.brokeredForwards;
      };
    };

  # forward-chain fragment sealing a bridge. egress "open": dns and declared
  # pinholes plus the internet, every other private range dropped. egress
  # "closed": nothing but the declared pinholes, dns included in nothing.
  # replies to whatever was allowed flow back either way.
  # counters and comments feed `fencr dashboard`; drops also log with a
  # rate limit so the journal shows who knocked without flooding
  forwardFilterFragment =
    cfg:
    let
      tag = kind: ''comment "fencr:${cfg.name}:${kind}"'';
      sealed = "{ ${lib.concatStringsSep ", " specialUseNetworks.v4} }";
    in
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
    ''
    + lib.optionalString (cfg.egress == "open") ''
      iifname "${cfg.bridge}" ip daddr ${cfg.dns} udp dport 53 counter accept ${tag "dns"}
      iifname "${cfg.bridge}" ip daddr ${cfg.dns} tcp dport 53 counter accept ${tag "dns-tcp"}
    ''
    + lib.concatMapStringsSep "\n" (
      destination:
      ''iifname "${cfg.bridge}" ip daddr ${destination.address} tcp dport ${toString destination.port} counter accept ${tag "pin-${destination.address}-${toString destination.port}"}''
    ) cfg.allowedTCPDestinations
    + "\n"
    + (
      if cfg.egress == "open" then
        ''
          iifname "${cfg.bridge}" ip daddr ${sealed} limit rate 5/second log prefix "fencr-${cfg.name}-blocked: "
          iifname "${cfg.bridge}" ip daddr ${sealed} counter drop ${tag "blocked-private"}
          iifname "${cfg.bridge}" counter accept ${tag "internet"}
        ''
      else
        ''
          iifname "${cfg.bridge}" limit rate 5/second log prefix "fencr-${cfg.name}-blocked: "
          iifname "${cfg.bridge}" counter drop ${tag "blocked"}
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
      iifname "${cfg.bridge}" tcp dport { ${
        lib.concatMapStringsSep ", " toString ports
      } } counter accept comment "fencr:${cfg.name}:host"
    ''
    + ''
      iifname "${cfg.bridge}" limit rate 5/second log prefix "fencr-${cfg.name}-host-blocked: "
      iifname "${cfg.bridge}" counter drop comment "fencr:${cfg.name}:host-blocked"
    '';

  # the seal as complete nftables tables. both frontends install exactly this
  # text: the nixos module as networking.nftables.tables, the flakelet unit
  # with nft -f. the tables stand on their own so no frontend chain runs
  # ahead of them, and so the same text can be loaded and probed in a test
  firewallOf =
    cfg:
    let
      tables = {
        "fencr-${cfg.name}-nat" = {
          family = "ip";
          content = ''
            chain postrouting {
              type nat hook postrouting priority srcnat; policy accept;
              ${natRuleFragment cfg}
            }
          '';
        };
        "fencr-${cfg.name}" = {
          family = "inet";
          content = ''
            chain forward {
              type filter hook forward priority filter; policy accept;
              ${forwardFilterFragment cfg}
              oifname "${cfg.bridge}" drop
            }
            chain input {
              type filter hook input priority -1; policy accept;
              ${sealInputFragment cfg cfg.hostPorts}
            }
          '';
        };
      };
    in
    {
      inherit tables;
      standalone = lib.concatStrings (
        lib.mapAttrsToList (name: table: ''
          table ${table.family} ${name} {
            ${table.content}
          }
        '') tables
      );
    };

  # the environment itself: hardware shape, network posture, and a /var/lib
  # that survives reboots so whatever is installed inside keeps its state.
  guestBase =
    {
      agentSandbox,
      lib,
      modulesPath,
      pkgs,
      ...
    }:
    {
      imports = [ "${modulesPath}/profiles/minimal.nix" ];

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

        inherit (agentSandbox) credentialFiles;

        shares = [
          {
            source = "/nix/store";
            mountPoint = "/nix/.ro-store";
            tag = "ro-store";
            proto = "virtiofs";
          }
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

      system.switch.enable = false;

      # the host connects over vsock, so every forwarded port needs a listener
      # on the guest side of it. the relayed service itself only binds
      # loopback. host forwards get the mirror image: a loopback listener
      # relayed to the host's vsock cid.
      systemd.services = lib.mkMerge [
        (lib.mkIf (agentSandbox.secretNames != [ ]) {
          fencr-secrets = {
            description = "Materialize fencr credentials in volatile guest storage";
            wantedBy = [ "sysinit.target" ];
            before = [ "sysinit.target" ];
            after = [ "local-fs.target" ];
            requires = [ "local-fs.target" ];
            unitConfig.DefaultDependencies = false;
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              ImportCredential = agentSandbox.secretNames;
            };
            script = ''
              install -d -m 0700 /run/agent-secrets
              ${lib.concatMapStringsSep "\n" (
                secretName:
                "install -m 0400 \"$CREDENTIALS_DIRECTORY/${secretName}\" /run/agent-secrets/${secretName}"
              ) agentSandbox.secretNames}
            '';
          };
        })
        (lib.mkIf (agentSandbox.sshKeys != [ ]) {
          sshd.wantedBy = lib.mkForce [ ];
          "fencr-sshd-vsock@" = {
            description = "sshd for a fencr vsock connection";
            unitConfig.CollectMode = "inactive-or-failed";
            serviceConfig = {
              ExecStart = "-${pkgs.openssh}/bin/sshd -i -f /etc/ssh/sshd_config";
              StandardInput = "socket";
              StandardError = "journal";
            };
          };
        })
        (lib.listToAttrs (
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
        ))
      ];

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

      # fencr owns vsock port 22 rather than merging with the socket emitted
      # by systemd-ssh-generator
      boot.kernelParams = [ "systemd.ssh_auto=0" ];
      systemd.sockets.fencr-sshd-vsock = lib.mkIf (agentSandbox.sshKeys != [ ]) {
        description = "sshd on fencr vsock";
        wantedBy = [ "sockets.target" ];
        listenStreams = [ "vsock::22" ];
        socketConfig = {
          Accept = true;
          MaxConnections = 16;
        };
      };
      # /etc is rebuilt on every boot, so keep the host key on the state
      # volume; otherwise the host's known_hosts breaks each time
      systemd.tmpfiles.rules = [ "d /var/lib/ssh 0700 root root - -" ];

      services.openssh = {
        enable = agentSandbox.sshKeys != [ ];
        openFirewall = false;
        settings.PasswordAuthentication = false;
        hostKeys = [
          {
            path = "/var/lib/ssh/ssh_host_ed25519_key";
            type = "ed25519";
          }
        ];
      };

      users.users.root.openssh.authorizedKeys.keys = agentSandbox.sshKeys;

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

      documentation.enable = false;
      environment.defaultPackages = lib.mkForce [ ];
      environment.systemPackages = [ ];
      nix.enable = lib.mkDefault false;
      programs.nano.enable = false;

      system.stateVersion = lib.versions.majorMinor lib.version;
    };
}
