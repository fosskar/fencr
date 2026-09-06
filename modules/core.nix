# the builders behind the nixos module: instance derivation, firewall rule
# text, forward transports, the credential proxies and the guest system. pure
# functions of an instance, so checks/core.nix probes them without a host.
{ lib }:
rec {
  # applied again in resolveInstance, so a check that omits an option still
  # gets the same vm the module would build
  defaults = {
    vcpu = 4;
    mem = 4096;
    memoryMax = "4608M";
    cpuQuota = "400%";
    stateSize = 32768;
    egress = "closed";
    prefixLength = 24;
    credentials = [ ];
    allowedDomains = [ ];
    allowedTCPDestinations = [ ];
    expose = [ ];
    hostForwards = [ ];
    hostPorts = [ ];
    secrets = { };
  };

  tapOf = name: "tap-${name}";
  bridgeOf = name: "br-${name}";
  macOf = cfg: "02:00:00:00:20:0${toString (cfg.id + 1)}";
  cidOf = cfg: 3 + cfg.id;
  hostIpOf = cfg: "10.30.${toString (cfg.id + 1)}.1";
  ipOf = cfg: "10.30.${toString (cfg.id + 1)}.2";
  subnetOf = cfg: "10.30.${toString (cfg.id + 1)}.0/24";

  stateDirOf = name: "/var/lib/fencr-vms/${name}";
  stateImageOf = name: "${stateDirOf name}/state.img";
  userOf = name: "fencr-${name}";
  vmUnitOf = name: "fencr-${name}.service";

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
        "2024"
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
    StandardInput = "socket";
    StandardError = "journal";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_VSOCK"
    ];
  };

  # the hypervisor unit: the microvm.nix runner under the vm's own system
  # user in group kvm, so two vms' crosvm processes share no host identity
  # and the state image has a stable owner. AF_INET is for the tap ioctls
  # only. crosvm's jails remount /proc, so those two knobs of the shared
  # set stay off. the runner creates the state image on first start; a
  # larger stateSize grows it here and the guest grows the filesystem
  vmService =
    pkgs: instance: runner:
    let
      runDir = "/run/fencr-${instance.name}";
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
          ExecStartPre = pkgs.writeShellScript "fencr-${instance.name}-grow" ''
            set -eu
            if [ -e ${image} ] && [ "$(${pkgs.coreutils}/bin/stat -c %s ${image})" -lt $((${toString instance.stateSize} * 1048576)) ]; then
              ${pkgs.coreutils}/bin/truncate -s ${toString instance.stateSize}M ${image}
            fi
          '';
          ExecStart = "${runner}/bin/microvm-run";
          # microvm-shutdown only presses the power button; waiting for
          # crosvm to exit is what lets the guest unmount its state
          ExecStop = pkgs.writeShellScript "fencr-${instance.name}-stop" ''
            ${runner}/bin/microvm-shutdown
            while [ -d /proc/$MAINPID ]; do sleep 0.5; done
          '';
          User = userOf instance.name;
          RuntimeDirectory = "fencr-${instance.name}";
          WorkingDirectory = runDir;
          Restart = "on-failure";
          RestartSec = 5;
          MemoryMax = instance.memoryMax;
          CPUQuota = instance.cpuQuota;
          CPUWeight = 20;
          LoadCredential = lib.mapAttrsToList (
            secretName: source: "${secretName}:${source}"
          ) instance.secrets;
          ReadWritePaths = [
            runDir
            (stateDirOf instance.name)
          ];
          DevicePolicy = "closed";
          DeviceAllow = [
            "/dev/kvm rw"
            "/dev/net/tun rw"
            "/dev/vhost-vsock rw"
          ];
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_INET"
          ];
          IPAddressDeny = "any";
          RestrictNamespaces = "user mnt pid net";
        };
    };

  # crosvm's fw_cfg device carries the systemd credentials but has no acpi
  # node; this is the node qemu's own dsdt declares for it, at the same port
  fwCfgTable =
    pkgs:
    pkgs.runCommand "fencr-fw-cfg-ssdt" { nativeBuildInputs = [ pkgs.acpica-tools ]; } ''
      cat > fwcfg.dsl <<'EOF'
      DefinitionBlock ("", "SSDT", 2, "FENCR", "FWCFG", 1)
      {
          Scope (\_SB)
          {
              Device (FWCF)
              {
                  Name (_HID, "QEMU0002")
                  Name (_STA, 0x0B)
                  Name (_CRS, ResourceTemplate ()
                  {
                      IO (Decode16, 0x0510, 0x0510, 0x01, 0x0C)
                  })
              }
          }
      }
      EOF
      iasl -p out fwcfg.dsl
      cp out.aml $out
    '';

  credentialFilesOf =
    vmUnit: secretNames:
    lib.genAttrs secretNames (secretName: "/run/credentials/${vmUnit}/${secretName}");

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

  # host to guest ("expose"), both ends in one place: the host socket unit and
  # the per-connection relay that splice an accepted tcp connection to the
  # guest's vsock port, and the guest listener that hands it to loopback.
  # the guest end cannot tell host clients apart: vsock connect needs no
  # privilege, so every host account reaches the guest port directly, and
  # listenAddress only narrows the tcp side
  exposeUnits = {
    socket = instance: forward: {
      description = "forward to ${instance.name} guest port ${toString forward.guestPort}";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "${forward.listenAddress}:${toString forward.listenPort}";
        Accept = true;
        MaxConnections = 64;
      };
    };
    service = pkgs: instance: vmUnit: forward: {
      description = "forward to ${instance.name} guest port ${toString forward.guestPort}";
      after = [ vmUnit ];
      requires = [ vmUnit ];
      unitConfig.CollectMode = "inactive-or-failed";
      serviceConfig = forwardHardening // {
        ExecStart = "${pkgs.socat}/bin/socat STDIO VSOCK-CONNECT:${toString instance.cid}:${toString forward.guestPort}";
      };
    };
    guest = pkgs: forward: {
      name = "fencr-vsock-proxy-${toString forward.guestPort}";
      value = {
        description = "vsock proxy for port ${toString forward.guestPort}";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = proxyHardening // {
          ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString forward.guestPort},fork TCP:127.0.0.1:${toString forward.guestPort}";
        };
      };
    };
  };

  # guest to host, the mirror image: a guest loopback listener relayed to the
  # host's cid, the host's vsock socket unit, and a cid-checked relay that
  # splices the connection to a host loopback port or, for a granted
  # credential, to its proxy's unix socket
  hostForwardUnits = {
    socket = instance: forward: {
      description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "vsock::${toString forward.vsockPort}";
        Accept = true;
        MaxConnections = 64;
        TriggerLimitIntervalSec = 0;
      };
    };
    service =
      pkgs: instance: vmUnit: forward:
      let
        target =
          if forward.credential != null then
            "unix:${credentialSocketOf instance forward}"
          else
            toString forward.targetPort;
      in
      {
        description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
        after = [ vmUnit ];
        requires = [ vmUnit ];
        unitConfig.CollectMode = "inactive-or-failed";
        serviceConfig =
          forwardHardening
          // {
            ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward ${toString instance.cid} ${target}";
          }
          // lib.optionalAttrs (forward.credential != null) {
            SupplementaryGroups = [ "kvm" ];
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_VSOCK"
              "AF_UNIX"
            ];
          };
      };
    guest = pkgs: forward: {
      name = "fencr-vsock-host-proxy-${toString forward.targetPort}";
      value = {
        description = "host vsock proxy for port ${toString forward.targetPort}";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = proxyHardening // {
          ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:${toString forward.targetPort},bind=127.0.0.1,fork VSOCK-CONNECT:2:${toString forward.vsockPort}";
        };
      };
    };
  };

  # domain-allowlist egress: the guest's resolver is the bridge address,
  # where the egress proxy answers every name with itself, so every tls
  # connection lands on the host and is judged by the server name in its
  # client hello; nothing is decrypted and no dns leaves the host
  proxyOf = cfg: cfg.allowedDomains != [ ];

  # a granted credential is a host forward whose target is its proxy's unix
  # socket; the guest sees it as one loopback port, named in agentSandbox
  credentialPortsOf =
    credentials:
    lib.listToAttrs (
      lib.imap0 (i: name: lib.nameValuePair name (14000 + i)) (lib.attrNames credentials)
    );

  hostForwardsOf =
    cfg: credentials:
    map (forward: forward // { credential = null; }) cfg.hostForwards
    ++ map (name: {
      vsockPort = (credentialPortsOf credentials).${name};
      targetPort = (credentialPortsOf credentials).${name};
      credential = credentials.${name} // {
        inherit name;
      };
    }) (lib.filter (name: credentials ? ${name}) cfg.credentials);

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

  egressProxyBin =
    pkgs:
    pkgs.writers.writeRustBin "fencr-egress-proxy" {
      rustcArgs = [
        "-O"
        "--edition"
        "2024"
      ];
    } ./egress-proxy.rs;

  # listens on the bridge address only, so the guest's subnet is allowed in
  # beside the internet; every other private range stays denied, and an
  # allowed name resolving into the lan goes nowhere
  egressProxyServiceConfig =
    pkgs: instance:
    proxyHardening
    // {
      ExecStart = "${egressProxyBin pkgs}/bin/fencr-egress-proxy ${instance.hostIp} ${
        pkgs.writeText "fencr-egress-domains" (
          lib.concatMapStrings (domain: "${domain}\n") instance.allowedDomains
        )
      }";
      CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
      AmbientCapabilities = "CAP_NET_BIND_SERVICE";
      # resolving on the host goes through resolved, over its unix socket
      # or its stub on 127.0.0.53
      IPAddressAllow = [
        "0.0.0.0/0"
        "::/0"
        "127.0.0.53/32"
        instance.subnet
      ];
      IPAddressDeny = specialUseNetworks.v4 ++ specialUseNetworks.v6;
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
      ];
    };

  # a credential proxy: the guest talks plain http through the vsock
  # forward; this proxy holds the secret and injects the header on the host
  # side, so the value never exists inside the vm. it listens on a unix
  # socket in its own runtime directory, group kvm, so only the cid-checked
  # relay reaches it: no host loopback port, nothing for another host
  # process to borrow the credential through. the upstream may be https;
  # caddy originates that tls on the host, the guest never sees a cert
  credentialRuntimeDirOf = cfg: forward: "fencr-credential-${cfg.name}-${forward.credential.name}";

  credentialSocketOf = cfg: forward: "/run/${credentialRuntimeDirOf cfg forward}/credential.sock";

  credentialCaddyfile =
    pkgs: socket: credential:
    pkgs.writeText "fencr-credential.caddyfile" ''
      {
        admin off
        auto_https off
      }
      http:// {
        bind unix/${socket}|0660
        reverse_proxy ${credential.upstream} {
          header_up Host {upstream_hostport}
          header_up ${credential.header} "{$FENCR_CREDENTIAL}"
        }
      }
    '';

  credentialExec =
    pkgs: socket: credential:
    pkgs.writeShellScript "fencr-credential" ''
      FENCR_CREDENTIAL="$(cat "$CREDENTIALS_DIRECTORY/secret")"
      export FENCR_CREDENTIAL
      exec ${pkgs.caddy}/bin/caddy run --config ${
        credentialCaddyfile pkgs socket credential
      } --adapter caddyfile
    '';

  # the upstream is loopback or the internet; a private range is never a
  # credential target, so an allowed name cannot resolve into the lan
  credentialServiceConfig =
    pkgs: cfg: forward:
    proxyHardening
    // {
      ExecStart = "${credentialExec pkgs (credentialSocketOf cfg forward) forward.credential}";
      LoadCredential = "secret:${forward.credential.secretFile}";
      Environment = [
        "XDG_DATA_HOME=/tmp"
        "XDG_CONFIG_HOME=/tmp"
      ];
      Group = "kvm";
      RuntimeDirectory = credentialRuntimeDirOf cfg forward;
      RuntimeDirectoryMode = "0750";
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

  duplicates =
    values: lib.unique (lib.filter (value: lib.count (other: other == value) values > 1) values);

  resolveInstance =
    {
      name,
      sshKeys ? [ ],
      credentials ? { },
      ...
    }@args:
    let
      options = defaults // args.options;
      invalidSecretNames = lib.filter (secretName: builtins.match "[A-Za-z0-9_.-]+" secretName == null) (
        lib.attrNames options.secrets
      );
      guest = {
        inherit name sshKeys;
        inherit (options)
          vcpu
          mem
          stateSize
          prefixLength
          ;
        # with a domain allowlist the egress proxy is the guest's resolver
        dns = if proxyOf options then hostIpOf options else options.dns;
        tap = tapOf name;
        bridge = bridgeOf name;
        mac = macOf options;
        cid = cidOf options;
        hostIp = hostIpOf options;
        ip = ipOf options;
        expose = map parseExpose options.expose;
        hostForwards = hostForwardsOf options credentials;
        credentials = lib.genAttrs options.credentials (credential: {
          port = (credentialPortsOf credentials).${credential};
        });
        secretNames = lib.attrNames options.secrets;
      };
      errors =
        lib.optional (options.id < 0 || options.id > 8) "${name}: id must be between 0 and 8"
        ++ map (
          secretName:
          "${name}: secret name \"${secretName}\" contains characters unsupported by systemd credentials"
        ) invalidSecretNames
        ++ lib.optional (
          lib.stringLength guest.tap > 15
        ) "vm name \"${name}\" is too long: \"${guest.tap}\" exceeds IFNAMSIZ"
        ++ lib.optional (
          options.allowedDomains != [ ] && options.egress != "closed"
        ) "${name}: allowedDomains requires egress = \"closed\""
        ++ map (error: "${name}: invalid allowedDomains ${error}") (
          domainPatternErrors options.allowedDomains
        )
        ++ map (credential: "${name}: credential \"${credential}\" is not declared in fencr.credentials") (
          lib.filter (credential: !(credentials ? ${credential})) options.credentials
        )
        ++ map (port: "${name}: expose port ${toString port} declared twice") (
          duplicates (map (forward: forward.listenPort) guest.expose)
        )
        ++ map (port: "${name}: hostForward vsock port ${toString port} declared twice") (
          duplicates (map (forward: forward.vsockPort) guest.hostForwards)
        )
        ++ map (port: "${name}: hostForward target port ${toString port} declared twice") (
          duplicates (map (forward: forward.targetPort) guest.hostForwards)
        );
    in
    guest
    // {
      inherit guest errors;
      inherit (options)
        id
        memoryMax
        cpuQuota
        egress
        allowedDomains
        hostPorts
        secrets
        ;
      allowedTCPDestinations = map parseDestination options.allowedTCPDestinations;
      proxy = proxyOf options;
      subnet = subnetOf options;
      credentialForwards = lib.filter (forward: forward.credential != null) guest.hostForwards;
      # the ports also name the socket units; the listen address is no
      # separator, a second bind on the port fails either way
      forwardEndpoints =
        map (forward: "tcp:${toString forward.listenPort}") guest.expose
        ++ map (forward: "vsock:${toString forward.vsockPort}") guest.hostForwards;
    };

  fleetErrors =
    instances:
    let
      values = lib.attrValues instances;
    in
    lib.optional (duplicates (map (instance: instance.id) values) != [ ]) "instance ids must be unique"
    ++ lib.optional (
      duplicates (lib.concatMap (instance: instance.forwardEndpoints) values) != [ ]
    ) "host listen endpoints must be unique across instances";

  hostUnits =
    pkgs: instance:
    let
      vmUnit = vmUnitOf instance.name;
      forwardName = forward: "${instance.name}-forward-${toString forward.listenPort}";
      hostForwardName = forward: "${instance.name}-host-forward-${toString forward.vsockPort}";
      proxyName = "${instance.name}-egress-proxy";
      credentialName = forward: "${instance.name}-credential-${forward.credential.name}";
      forwardServices = map (forward: {
        name = "${forwardName forward}@";
        value = exposeUnits.service pkgs instance vmUnit forward;
      }) instance.expose;
      hostForwardServices = map (forward: {
        name = "${hostForwardName forward}@";
        value = hostForwardUnits.service pkgs instance vmUnit forward;
      }) instance.hostForwards;
      credentialServices = map (forward: {
        name = credentialName forward;
        value = {
          description = "credential ${forward.credential.name} for ${instance.name}";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = credentialServiceConfig pkgs instance forward;
        };
      }) instance.credentialForwards;
      forwardSockets = map (forward: {
        name = forwardName forward;
        value = exposeUnits.socket instance forward;
      }) instance.expose;
      hostForwardSockets = map (forward: {
        name = hostForwardName forward;
        value = hostForwardUnits.socket instance forward;
      }) instance.hostForwards;
    in
    {
      services =
        lib.listToAttrs (forwardServices ++ hostForwardServices ++ credentialServices)
        // lib.optionalAttrs instance.proxy {
          ${proxyName} = {
            description = "domain-allowlist egress proxy for ${instance.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ];
            serviceConfig = egressProxyServiceConfig pkgs instance;
          };
        };
      sockets = lib.listToAttrs (forwardSockets ++ hostForwardSockets);
      # what the guest system is built against: the resolved contract plus
      # where the vm unit stages each secret for fw_cfg
      guest = instance.guest // {
        credentialFiles = credentialFilesOf vmUnit instance.guest.secretNames;
      };
      unitNames = {
        vm = vmUnit;
        sockets =
          map (forward: {
            unit = "${forwardName forward}.socket";
            label = "host -> guest: ${forward.listenAddress}:${toString forward.listenPort} -> guest ${toString forward.guestPort}";
          }) instance.expose
          ++ map (forward: {
            unit = "${hostForwardName forward}.socket";
            label = "guest -> host: vsock ${toString forward.vsockPort} -> host ${toString forward.targetPort}";
          }) instance.hostForwards;
        proxy = lib.optional instance.proxy "${proxyName}.service";
        credentials = map (forward: "${credentialName forward}.service") instance.credentialForwards;
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

  # input-chain fragment sealing the vms' host access to the declared ports;
  # v6 dropped first like on forward: the host's own link-local multicast
  # reflects off the bridge
  sealInputFragment =
    cfg: ports:
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
      iifname "${cfg.bridge}" ct state established,related accept
    ''
    + lib.optionalString (ports != [ ]) ''
      iifname "${cfg.bridge}" tcp dport { ${
        lib.concatMapStringsSep ", " toString ports
      } } counter accept comment "fencr:${cfg.name}:host"
    ''
    + lib.optionalString cfg.proxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport 53 counter accept comment "fencr:${cfg.name}:egress-dns"
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport 443 counter accept comment "fencr:${cfg.name}:egress-tls"
    ''
    + ''
      iifname "${cfg.bridge}" limit rate 5/second log prefix "fencr-${cfg.name}-host-blocked: "
      iifname "${cfg.bridge}" counter drop comment "fencr:${cfg.name}:host-blocked"
    '';

  # the seal as complete nftables tables for networking.nftables.tables. they
  # stand on their own so no host chain runs ahead of them; both chains sit
  # one below filter, since a host chain at the same priority would tie
  firewallOf = cfg: {
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
          type filter hook forward priority filter - 1; policy accept;
          ${forwardFilterFragment cfg}
          oifname "${cfg.bridge}" drop
        }
        chain input {
          type filter hook input priority filter - 1; policy accept;
          ${sealInputFragment cfg cfg.hostPorts}
        }
      '';
    };
  };

  # the environment itself: hardware shape, network posture, and a /var/lib
  # that survives reboots so whatever is installed inside keeps its state.
  guestBase =
    microvmSrc:
    {
      agentSandbox,
      config,
      lib,
      modulesPath,
      pkgs,
      ...
    }:
    let
      # microvm.nix's crosvm runner uses the deprecated -r, whose root=/dev/vda
      # breaks the systemd initrd, and boots the 380 MiB unstripped vmlinux
      patchedMicrovm = pkgs.applyPatches {
        name = "microvm.nix";
        src = microvmSrc;
        patches = [ ./microvm-crosvm-block.patch ];
      };
    in
    {
      imports = [ "${modulesPath}/profiles/minimal.nix" ];

      networking.hostName = lib.mkDefault agentSandbox.name;

      microvm = {
        hypervisor = "crosvm";
        runner.crosvm = lib.mkForce (
          import "${patchedMicrovm}/lib/runner.nix" {
            inherit pkgs;
            microvmConfig = config.microvm // {
              inherit (config.networking) hostName;
              hypervisor = "crosvm";
            };
            inherit (config.system.build) toplevel;
          }
        );
        inherit (agentSandbox) vcpu mem;
        balloon = true;
        vsock.cid = agentSandbox.cid;

        interfaces = [
          {
            type = "tap";
            id = agentSandbox.tap;
            inherit (agentSandbox) mac;
          }
        ];

        # the state tree is a disk image the runner creates on first start;
        # no share, so no file server faces the guest and without a host
        # store share the guest's closure becomes an erofs image
        volumes = [
          {
            image = stateImageOf agentSandbox.name;
            label = "fencr-state";
            mountPoint = "/var/lib";
            size = agentSandbox.stateSize;
          }
        ];

        # credentials go through fw_cfg, which microvm.nix's runner refuses
        crosvm.extraArgs = lib.optionals pkgs.stdenv.hostPlatform.isx86_64 (
          [
            "--nested"
            "mode=off"
            "--acpi-table"
            "${fwCfgTable pkgs}"
          ]
          ++ lib.concatMap (secretName: [
            "--fw-cfg"
            "name=opt/io.systemd.credentials/${secretName},path=${agentSandbox.credentialFiles.${secretName}}"
          ]) agentSandbox.secretNames
        );
      };

      fileSystems."/var/lib".autoResize = true;
      boot.initrd.kernelModules = lib.optional pkgs.stdenv.hostPlatform.isx86_64 "qemu_fw_cfg";
      assertions = [
        {
          assertion = pkgs.stdenv.hostPlatform.isx86_64 || agentSandbox.secretNames == [ ];
          message = "fencr: secrets reach a crosvm guest through fw_cfg, which only x86_64 gets";
        }
      ];

      system.switch.enable = false;
      # perl-free activation, as the perlless profile sets it; the profile's
      # ban on perl in the closure is not taken, payloads may need it
      boot.initrd.systemd.enable = true;
      system.etc.overlay.enable = true;
      services.userborn.enable = true;

      # the guest ends of the forwards; the host ends live beside them in
      # exposeUnits and hostForwardUnits
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
          map (exposeUnits.guest pkgs) agentSandbox.expose
          ++ map (hostForwardUnits.guest pkgs) agentSandbox.hostForwards
        ))
      ];

      networking = {
        useDHCP = false;
        useNetworkd = true;
        firewall.enable = true;
        # the iptables backend drags perl in through libpcap and rdma-core
        nftables.enable = true;
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

      documentation.enable = false;
      environment.defaultPackages = lib.mkForce [ ];
      environment.systemPackages = [ ];
      nix.enable = lib.mkDefault false;
      programs.nano.enable = false;

      system.stateVersion = lib.versions.majorMinor lib.version;
    };
}
