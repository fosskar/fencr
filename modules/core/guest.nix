{ core, ... }:
let
  inherit (core)
    stateImageOf
    vsockOf
    powerPort
    secretsPort
    trustVariables
    ;
in
{

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
      systemd.services = lib.mkMerge [
        (lib.mkIf (agentSandbox.secretNames != [ ] || agentSandbox.credentialDomains != [ ]) {
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
              test -e /run/agent-secrets/${lib.head (agentSandbox.secretNames ++ [ "fencr-ca.crt" ])}
              chmod 0400 /run/agent-secrets/*
            ''
            + lib.optionalString (agentSandbox.credentialDomains != [ ]) ''
              install -d -m 0755 /run/fencr
              install -m 0444 /run/agent-secrets/fencr-ca.crt /run/fencr/ca.crt
              rm /run/agent-secrets/fencr-ca.crt
              cat ${config.security.pki.caBundle} /run/fencr/ca.crt > /run/fencr/ca-bundle.crt
              chmod 0444 /run/fencr/ca-bundle.crt
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
      ];
      networking = {
        useDHCP = false;
        useNetworkd = true;
        # the bridge is the one interface: sshd when keys authorize it,
        # and the exposed ports, reachable at the guest's address
        firewall = {
          enable = true;
          allowedTCPPorts = lib.optional (agentSandbox.sshKeys != [ ]) 22 ++ agentSandbox.expose;
        };
        # the iptables backend drags perl in through libpcap and rdma-core
        nftables.enable = true;
        # a credential's domain is the host, where its proxy answers with a
        # certificate from the host's authority
        hosts = lib.mkIf (agentSandbox.credentialDomains != [ ]) {
          ${agentSandbox.hostIp} = agentSandbox.credentialDomains;
        };
      };
      # the system trust store, fetched at boot with the host's authority in
      # it, on every path the store bundle sits on; python's certifi and
      # node carry bundles of their own and read only these variables
      environment.etc = lib.mkIf (agentSandbox.credentialDomains != [ ]) (
        lib.genAttrs
          [
            "ssl/certs/ca-certificates.crt"
            "ssl/certs/ca-bundle.crt"
            "pki/tls/certs/ca-bundle.crt"
          ]
          (_: {
            source = lib.mkForce "/run/fencr/ca-bundle.crt";
          })
      );
      environment.sessionVariables = lib.mkIf (agentSandbox.credentialDomains != [ ]) trustVariables;
      systemd.globalEnvironment = lib.mkIf (agentSandbox.credentialDomains != [ ]) trustVariables;
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
      # no sshd on vsock from systemd-ssh-generator: the door is the bridge
      boot.kernelParams = [ "systemd.ssh_auto=0" ];
      # /etc is rebuilt on every boot, so keep the host key on the state
      # volume; otherwise the host's known_hosts breaks each time
      systemd.tmpfiles.rules = [ "d /var/lib/ssh 0700 root root - -" ];
      # socket-activated on the guest's address; the socket binds before
      # networkd assigns it
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
