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
  # firecracker's vsock on the host: one unix socket for connections into
  # the guest, and one per port, "<vsock>_<port>", for connections out of
  # it. the directory admits the vm's user and group kvm, which is what the
  # relays run with; nobody else on the host reaches a vm this way
  runDirOf = name: "/run/fencr-${name}";
  vsockOf = name: "${runDirOf name}/vsock";
  # the ssh door for every host account, a socket the relays open into the
  # guest's vsock port 22
  sshSocketOf = name: "/run/fencr-ssh-${name}";
  # the power button: a guest listener on this vsock port powers off on any
  # connection, and only the vm's user and group kvm can open the vsock
  powerPort = 4;
  # raw secrets: at boot the guest fetches them as one archive from a host
  # socket only the vm's own user can open; the host side reads them as
  # systemd credentials, so they touch neither the store nor a disk
  secretsPort = 5;

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
    SupplementaryGroups = [ "kvm" ];
    StandardInput = "socket";
    StandardError = "journal";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_UNIX"
    ];
  };

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
            ${vsockForwardBin pkgs}/bin/fencr-vsock-forward connect ${vsockOf instance.name} ${toString powerPort} </dev/null || true
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
  # the guest end cannot tell host clients apart: group kvm reaches the
  # guest port directly through the vm's vsock socket, and listenAddress
  # only narrows the tcp side
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
      requisite = [ vmUnit ];
      partOf = [ vmUnit ];
      unitConfig.CollectMode = "inactive-or-failed";
      serviceConfig = forwardHardening // {
        ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward connect ${vsockOf instance.name} ${toString forward.guestPort}";
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
  # host's cid, the host's socket unit on the path firecracker opens for that
  # port, and a relay that splices the connection to a host loopback port or,
  # for a granted credential, to its proxy's unix socket. the socket belongs
  # to the vm's user with no group or other access, so only that vm's
  # firecracker can open it: the path is the identity
  hostForwardUnits = {
    socket = instance: forward: {
      description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "${vsockOf instance.name}_${toString forward.vsockPort}";
        SocketUser = userOf instance.name;
        SocketMode = "0600";
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
        requisite = [ vmUnit ];
        partOf = [ vmUnit ];
        unitConfig.CollectMode = "inactive-or-failed";
        serviceConfig = forwardHardening // {
          ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward serve ${target}";
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
  # socket in its own runtime directory, group kvm, so only the vm's own
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
        ) (lib.filter (secretName: builtins.match "[A-Za-z0-9_.-]+" secretName == null) guest.secretNames)
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
      # the ssh door: a socket every host account may open, relayed into
      # the guest's vsock port 22; the key check happens in the guest
      sshName = "${instance.name}-ssh";
      sshUnits = lib.optionalAttrs (instance.sshKeys != [ ]) {
        socket.${sshName} = {
          description = "ssh into ${instance.name}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = sshSocketOf instance.name;
            SocketMode = "0666";
            Accept = true;
            MaxConnections = 16;
          };
        };
        service."${sshName}@" = {
          description = "ssh into ${instance.name}";
          after = [ vmUnit ];
          requisite = [ vmUnit ];
          partOf = [ vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          serviceConfig = forwardHardening // {
            ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward connect ${vsockOf instance.name} 22";
          };
        };
      };
      # raw secrets, served once per boot as a tar stream of the unit's
      # credentials directory into a connection the guest opened
      secretsName = "${instance.name}-secrets";
      secretsUnits = lib.optionalAttrs (instance.secrets != { }) {
        socket.${secretsName} = {
          description = "raw secrets for ${instance.name}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = "${vsockOf instance.name}_${toString secretsPort}";
            SocketUser = userOf instance.name;
            SocketMode = "0600";
            Accept = true;
            MaxConnections = 4;
            TriggerLimitIntervalSec = 0;
          };
        };
        service."${secretsName}@" = {
          description = "raw secrets for ${instance.name}";
          after = [ vmUnit ];
          requisite = [ vmUnit ];
          partOf = [ vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          serviceConfig = forwardHardening // {
            LoadCredential = lib.mapAttrsToList (
              secretName: source: "${secretName}:${source}"
            ) instance.secrets;
            ExecStart = pkgs.writeShellScript "fencr-${instance.name}-secrets" ''
              exec ${pkgs.gnutar}/bin/tar -C "$CREDENTIALS_DIRECTORY" -cf - .
            '';
          };
        };
      };
    in
    {
      services =
        lib.listToAttrs (forwardServices ++ hostForwardServices ++ credentialServices)
        // sshUnits.service or { }
        // secretsUnits.service or { }
        // lib.optionalAttrs instance.proxy {
          ${proxyName} = {
            description = "domain-allowlist egress proxy for ${instance.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ];
            serviceConfig = egressProxyServiceConfig pkgs instance;
          };
        };
      sockets =
        lib.listToAttrs (forwardSockets ++ hostForwardSockets)
        // sshUnits.socket or { }
        // secretsUnits.socket or { };
      # what the guest system is built against
      inherit (instance) guest;
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
          }) instance.hostForwards
          ++ lib.optional (instance.sshKeys != [ ]) {
            unit = "${sshName}.socket";
            label = "host -> guest: ssh";
          };
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
    _microvmSrc:
    {
      agentSandbox,
      config,
      lib,
      modulesPath,
      pkgs,
      ...
    }:
    {
      imports = [ "${modulesPath}/profiles/minimal.nix" ];

      networking.hostName = lib.mkDefault agentSandbox.name;

      microvm = {
        hypervisor = "firecracker";
        inherit (agentSandbox) vcpu mem;
        vsock.cid = agentSandbox.cid;
        # the runner's own vsock path lives in the working directory and is
        # wiped on every start; the forwards' sockets must not be
        firecracker.extraConfig.vsock.uds_path = vsockOf agentSandbox.name;
        # the runner boots the kernel's unstripped vmlinux, 400 MiB of debug
        # symbols per guest; firecracker below 1.17 takes no bzImage
        firecracker.extraConfig."boot-source".kernel_image_path =
          lib.mkIf pkgs.stdenv.hostPlatform.isx86_64 "${pkgs.runCommand "vmlinux-stripped"
            { nativeBuildInputs = [ pkgs.binutils ]; }
            ''
              strip -o $out ${config.boot.kernelPackages.kernel.dev}/vmlinux
            ''
          }";
        # the guest must not see the host's virtualization extensions: vmx
        # is cpuid leaf 1 ecx bit 5, svm leaf 0x80000001 ecx bit 2
        firecracker.cpu = lib.mkIf pkgs.stdenv.hostPlatform.isx86_64 (
          let
            clearBit = bit: "0b" + lib.concatStrings (lib.genList (i: if 31 - i == bit then "0" else "x") 32);
          in
          {
            cpuid_modifiers = [
              {
                leaf = "0x1";
                subleaf = "0x0";
                flags = 0;
                modifiers = [
                  {
                    register = "ecx";
                    bitmap = clearBit 5;
                  }
                ];
              }
              {
                leaf = "0x80000001";
                subleaf = "0x0";
                flags = 0;
                modifiers = [
                  {
                    register = "ecx";
                    bitmap = clearBit 2;
                  }
                ];
              }
            ];
          }
        );

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

      };

      fileSystems."/var/lib".autoResize = true;

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
          # the vsock device comes up with udev; the fetch waits for it
          fencr-secrets = {
            description = "Materialize fencr secrets in volatile guest storage";
            wantedBy = [ "sysinit.target" ];
            before = [ "sysinit.target" ];
            after = [ "local-fs.target" ];
            requires = [ "local-fs.target" ];
            unitConfig.DefaultDependencies = false;
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
            };
            script = ''
              install -d -m 0700 /run/agent-secrets
              for _ in $(seq 60); do
                if ${pkgs.socat}/bin/socat -u VSOCK-CONNECT:2:${toString secretsPort} - \
                    | ${pkgs.gnutar}/bin/tar -C /run/agent-secrets -xf - --no-same-owner --no-same-permissions; then
                  break
                fi
                sleep 0.5
              done
              test -e /run/agent-secrets/${lib.head agentSandbox.secretNames}
              chmod 0400 /run/agent-secrets/*
            '';
          };
        })
        {
          # firecracker exits on cpu reset; a power-off only halts the cpu
          # and leaves the process running
          fencr-power = {
            description = "power button on fencr vsock";
            wantedBy = [ "multi-user.target" ];
            serviceConfig.ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString powerPort},fork EXEC:'${pkgs.systemd}/bin/systemctl reboot'";
          };
        }
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
