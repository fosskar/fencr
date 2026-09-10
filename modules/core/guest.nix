{ core, ... }:
let
  inherit (core)
    stateImageOf
    vsockOf
    apiSocketOf
    powerPort
    secretsPort
    prefixLength
    guestTrust
    trustVariables
    guestPortsOf
    ;
in
{
  guestBase =
    {
      agentSandbox,
      config,
      lib,
      modulesPath,
      pkgs,
      ...
    }:
    let
      trusted = agentSandbox.credentialDomains != [ ];
      bandwidth = mib: {
        bandwidth = {
          size = mib * 1048576;
          one_time_burst = 0;
          refill_time = 1000;
        };
      };
    in
    {
      imports = [ "${modulesPath}/profiles/minimal.nix" ];
      networking.hostName = lib.mkDefault agentSandbox.name;
      microvm = {
        hypervisor = "firecracker";
        # nixpkgs' glibc build ships an empty seccomp policy; only musl gets the allowlist
        firecracker.package = pkgs.pkgsStatic.firecracker;
        inherit (agentSandbox) vcpu mem;
        vsock.cid = agentSandbox.cid;
        # the runner wipes its own vsock path on every start; the secrets socket beside it must survive
        firecracker.extraConfig.vsock.uds_path = vsockOf agentSandbox.name;
        # the runner's default socket name follows networking.hostName, which a payload may set
        socket = apiSocketOf agentSandbox.name;
        # firecracker's default cache ignores guest flushes; lists are not merged, so the
        # runner's drives are restated to set Writeback on the state image
        firecracker.extraConfig.drives = [
          {
            drive_id = "store";
            path_on_host = config.microvm.storeDisk;
            is_root_device = false;
            is_read_only = true;
            io_engine = config.microvm.firecracker.driveIoEngine;
          }
          (
            {
              drive_id = "state";
              path_on_host = stateImageOf agentSandbox.name;
              is_root_device = false;
              is_read_only = false;
              io_engine = config.microvm.firecracker.driveIoEngine;
              cache_type = "Writeback";
            }
            // lib.optionalAttrs (agentSandbox.diskBandwidth != null) {
              rate_limiter = bandwidth agentSandbox.diskBandwidth;
            }
          )
        ];
        firecracker.extraConfig.network-interfaces = lib.mkIf (agentSandbox.networkBandwidth != null) [
          {
            iface_id = agentSandbox.tap;
            host_dev_name = agentSandbox.tap;
            guest_mac = agentSandbox.mac;
            rx_rate_limiter = bandwidth agentSandbox.networkBandwidth;
            tx_rate_limiter = bandwidth agentSandbox.networkBandwidth;
          }
        ];
        firecracker.extraConfig.entropy = { };
        # firecracker below 1.17 takes no bzImage, and the dev output's vmlinux is 400 MiB
        firecracker.extraConfig."boot-source".kernel_image_path =
          lib.mkIf pkgs.stdenv.hostPlatform.isx86_64 "${pkgs.runCommand "vmlinux-stripped"
            { nativeBuildInputs = [ pkgs.binutils ]; }
            ''
              strip -o $out ${config.boot.kernelPackages.kernel.dev}/vmlinux
            ''
          }";
        # hide vmx (leaf 1 ecx bit 5) and svm (leaf 0x80000001 ecx bit 2) from the guest
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
        # no share: no file server faces the guest, and the closure becomes an erofs image
        volumes = [
          {
            image = stateImageOf agentSandbox.name;
            label = "fencr-state";
            mountPoint = "/";
            size = agentSandbox.stateSize;
          }
        ];
      };
      fileSystems."/".autoResize = true;
      system.switch.enable = false;
      # the perlless profile's activation, without its ban on perl in the closure
      boot.initrd.systemd.enable = true;
      system.etc.overlay.enable = true;
      services.userborn.enable = true;
      systemd.services = lib.mkMerge [
        (lib.mkIf (agentSandbox.secretNames != [ ] || trusted) {
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
              ExecStart = pkgs.replaceVarsWith {
                src = ./guest-secrets.sh;
                isExecutable = true;
                replacements = {
                  inherit (pkgs) runtimeShell;
                  inherit (guestTrust) member cert bundle;
                  socat = "${pkgs.socat}/bin/socat";
                  tar = "${pkgs.gnutar}/bin/tar";
                  port = toString secretsPort;
                  first = lib.head (agentSandbox.secretNames ++ [ guestTrust.member ]);
                  storeBundle = lib.optionalString trusted config.security.pki.caBundle;
                };
              };
            };
          };
        })
        {
          # firecracker exits on cpu reset; a power-off only halts and leaves the process
          fencr-power = {
            description = "power button on fencr vsock";
            wantedBy = [ "multi-user.target" ];
            serviceConfig.ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString powerPort},fork EXEC:'${pkgs.systemd}/bin/systemctl reboot'";
          };
        }
      ];
      networking = {
        useDHCP = false;
        useNetworkd = true;
        firewall = {
          enable = true;
          allowedTCPPorts = guestPortsOf agentSandbox;
        };
        # the iptables backend drags perl in through libpcap and rdma-core
        nftables.enable = true;
        hosts = lib.mkIf trusted {
          ${agentSandbox.hostIp} = agentSandbox.credentialDomains;
        };
      };
      # every path the store bundle sits on; certifi and node read only the two variables
      environment.etc = lib.mkIf trusted (
        lib.genAttrs
          [
            "ssl/certs/ca-certificates.crt"
            "ssl/certs/ca-bundle.crt"
            "pki/tls/certs/ca-bundle.crt"
          ]
          (_: {
            source = lib.mkForce guestTrust.bundle;
          })
      );
      environment.sessionVariables = lib.mkIf trusted trustVariables;
      systemd.globalEnvironment = lib.mkIf trusted trustVariables;
      # virtio's enp0sN names are unpredictable; v4 only so the host's v4 rules see everything
      systemd.network.networks."10-lan" = {
        matchConfig.MACAddress = agentSandbox.mac;
        networkConfig = {
          Address = "${agentSandbox.ip}/${toString prefixLength}";
          Gateway = agentSandbox.hostIp;
          DNS = lib.mkIf (agentSandbox.dns != null) agentSandbox.dns;
          IPv6AcceptRA = false;
          LinkLocalAddressing = "ipv4";
        };
      };
      # no systemd-ssh-generator sshd on vsock
      boot.kernelParams = [ "systemd.ssh_auto=0" ];
      # the socket binds before networkd assigns the address
      systemd.sockets.sshd.socketConfig.FreeBind = lib.mkIf (agentSandbox.sshKeys != [ ]) true;
      services.openssh = {
        enable = agentSandbox.sshKeys != [ ];
        startWhenNeeded = true;
        listenAddresses = [
          {
            addr = agentSandbox.ip;
            port = 22;
          }
        ];
        openFirewall = false;
        settings.PasswordAuthentication = false;
        hostKeys = [
          {
            path = "/etc/ssh/ssh_host_ed25519_key";
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
      # pinned to the release the state image first shipped under, not the nixpkgs pin
      system.stateVersion = lib.mkDefault "26.11";
    };
}
