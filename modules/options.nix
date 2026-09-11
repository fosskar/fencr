# the options of fencr: what a host declares, what a vm may be given
{ lib, ... }@host:
let
  core = import ./core { inherit lib; };
in
{
  options.fencr.guestSystems = lib.mkOption {
    type = lib.types.attrsOf lib.types.raw;
    readOnly = true;
    description = "the evaluated guest system of every vm, keyed by vm name.";
  };

  options.fencr.credentials = lib.mkOption {
    default = { };
    description = "credentials a vm may use without ever seeing the value, granted by name in fencr.vms.<name>.credentials.";
    type = lib.types.attrsOf (
      lib.types.submodule (
        { config, name, ... }:
        {
          options = {
            provider = lib.mkOption {
              type = lib.types.nullOr (lib.types.enum (lib.attrNames core.providers));
              default = if core.providers ? ${name} then name else null;
              defaultText = "the credential's name when it names a provider";
              description = ''
                a known api, which supplies upstream and header:
                ${lib.concatStringsSep ", " (lib.attrNames core.providers)}.
              '';
            };
            upstream = lib.mkOption {
              type = lib.types.str;
              example = "https://api.anthropic.com";
              description = ''
                where requests go, with the credential injected: a public
                https api or a plain http port on host loopback. private
                ranges are refused. required without a provider.
              '';
            };
            domain = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "mcp.fencr";
              description = ''
                the name a vm calls. it resolves to the host, where the
                credential's proxy answers with a certificate from the
                host's own authority, which the vm trusts. defaults to the
                upstream's host; an upstream on host loopback needs one.
              '';
            };
            header = lib.mkOption {
              type = lib.types.str;
              default = "Authorization";
              description = "request header that carries the credential.";
            };
            secretFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                host file with the raw header value, for example "Bearer x";
                never enters a vm. a write to it restarts the credential
                proxy, so a rotated token is served without a rebuild.
              '';
            };
            allow = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [
                "GET,HEAD *"
                "POST /repos/*/pulls"
              ];
              description = ''
                requests the credential may ride on, as "<methods> <path>":
                methods comma-separated or "*", a path with "*" standing
                for any characters or "*" alone for any path. a request
                matching no entry is answered 403 by the host and never
                reaches the upstream. empty allows every request.
              '';
            };
          };
          config = lib.mkIf (config.provider != null) {
            upstream = lib.mkDefault core.providers.${config.provider}.upstream;
            header = lib.mkDefault core.providers.${config.provider}.header;
          };
        }
      )
    );
  };

  options.fencr.adminKeys = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    description = ''
      public keys authorized as root in every vm.
      host root can always reach a vm regardless (it owns the hypervisor,
      the state tree and the console); this only makes that access ssh.
    '';
  };

  options.fencr.vms = lib.mkOption {
    default = { };
    description = "sealed agent microvms, keyed by vm name.";
    type = lib.types.attrsOf (
      lib.types.submodule (
        { config, name, ... }:
        {
          options = {
            id = lib.mkOption {
              type = lib.types.ints.between 0 (core.idRange - 1);
              default = core.idOf (lib.attrNames host.config.fencr.vms) name;
              defaultText = "position of the name among fencr.vms";
              description = ''
                unique instance index; derives subnet, mac and vsock cid.
                by default the vm's position in name order, so adding a vm
                whose name sorts earlier moves the ones after it; set it to
                keep a vm's address fixed.
              '';
            };

            ip = lib.mkOption {
              type = lib.types.str;
              readOnly = true;
              default = core.ipOf { inherit (config) id; };
              description = "the vm's address on its bridge, where its sshd and exposed ports answer.";
            };

            hostIp = lib.mkOption {
              type = lib.types.str;
              readOnly = true;
              default = core.hostIpOf { inherit (config) id; };
              description = "the host's address on the vm's bridge, where outbound host:<port> grants apply.";
            };

            services = lib.mkOption {
              type = lib.types.listOf lib.types.raw;
              default = [ ];
              description = "nixos modules to run inside the vm.";
            };

            authorizedKeys = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = ''
                public keys authorized as root in this vm — the owner tier.
                a vm belongs to whoever holds these keys; no host account
                needed. without adminKeys and authorizedKeys the vm has no
                ssh door at all.
              '';
            };

            specialArgs = lib.mkOption {
              type = lib.types.attrsOf lib.types.raw;
              default = { };
              description = "extra specialArgs handed to the guest's module system.";
            };

            vcpu = lib.mkOption {
              type = lib.types.int;
              default = core.defaults.vcpu;
            };
            mem = lib.mkOption {
              type = lib.types.int;
              default = core.defaults.mem;
              description = "guest memory in MiB.";
            };
            memoryMax = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = core.defaults.memoryMax;
              defaultText = "mem plus 512 MiB";
              description = "hard cap on the whole vm unit, enforced by the host: the guest's memory plus room for the hypervisor, when null.";
            };
            stateSize = lib.mkOption {
              type = lib.types.int;
              default = core.defaults.stateSize;
              description = ''
                size in MiB of the vm's root filesystem, a sparse disk image at
                /var/lib/fencr-vms/<name>/state.img. a larger value grows the
                image and its filesystem on the next start; it never shrinks.
              '';
            };
            cpuQuota = lib.mkOption {
              type = lib.types.str;
              default = core.defaults.cpuQuota;
            };
            diskBandwidth = lib.mkOption {
              type = lib.types.nullOr lib.types.ints.positive;
              default = core.defaults.diskBandwidth;
              example = 200;
              description = ''
                cap in MiB/s on the vm's reads and writes to its state image,
                enforced by the hypervisor's token bucket. null leaves the
                disk unlimited.
              '';
            };
            networkBandwidth = lib.mkOption {
              type = lib.types.nullOr lib.types.ints.positive;
              default = core.defaults.networkBandwidth;
              example = 50;
              description = ''
                cap in MiB/s on the vm's traffic in each direction, enforced
                by the hypervisor's token bucket on the tap. null leaves the
                network unlimited.
              '';
            };
            maxConnections = lib.mkOption {
              type = lib.types.ints.positive;
              default = core.defaults.maxConnections;
              description = ''
                connections the vm may hold open at once, counted by the
                host's connection tracking; a new connection beyond it is
                dropped and logged. protects the host's conntrack table from
                a port scan or a leaking tool.
              '';
            };
            checkpoints = {
              onStop = lib.mkOption {
                type = lib.types.bool;
                default = core.defaults.checkpoints.onStop;
                description = ''
                  copy the state image after every clean stop, so a rebuild
                  or a restore leaves the state it replaced behind as
                  "stop-<utc stamp>".
                '';
              };
              interval = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = core.defaults.checkpoints.interval;
                example = "hourly";
                description = ''
                  a systemd calendar expression; at each tick a running vm
                  is paused for the instant the copy takes and the result
                  is "timer-<utc stamp>". null for none.
                '';
              };
              keep = lib.mkOption {
                type = lib.types.ints.positive;
                default = core.defaults.checkpoints.keep;
                description = ''
                  how many of each automatic kind to keep; older ones are
                  removed when a new one lands. manual checkpoints from
                  `fencr checkpoint` stay until removed.
                '';
              };
            };
            secrets = lib.mkOption {
              type = lib.types.attrsOf lib.types.path;
              default = core.defaults.secrets;
              description = ''
                host files the guest fetches over vsock at boot into its
                volatile /run/agent-secrets, mode 0400. guest root can read
                these raw values. for a key a program must hold itself, a
                signing key or a recovery key; an http api key is a
                credential instead, which the vm can use but never read.
              '';
            };

            outbound = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = core.defaults.outbound;
              example = [
                "github.com"
                "*.github.com"
                "!gist.github.com"
                "host:8080"
                "192.168.1.0/24:8123"
              ];
              description = ''
                connections the vm may initiate: a domain grants TLS on 443,
                host:<port> grants TCP to the host, and <ipv4[/prefix]>:<port>
                grants TCP to that address or subnet, including private ranges.
                "internet" grants public IPv4 internet access and DNS, excluding
                special-use ranges; it cannot accompany domain grants.
                "*.github.com" does not include "github.com". "!name" refuses
                a name a wildcard grant would otherwise admit. domains use the
                host's SNI proxy, without TLS interception or external DNS.
                empty means no explicit grants, including DNS. credential
                grants enable their own access independently.
              '';
            };

            inbound = lib.mkOption {
              type = lib.types.listOf lib.types.port;
              default = core.defaults.inbound;
              example = [ 9119 ];
              description = ''
                guest TCP ports any host process may reach at the vm's bridge
                address. the guest service must listen on that address, not
                loopback. ports are not published to the LAN or internet.
                SSH access is enabled separately by authorized keys.
              '';
            };

            credentials = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = core.defaults.credentials;
              example = lib.literalExpression ''[ "anthropic" ]'';
              description = ''
                names from fencr.credentials this vm may use. the vm calls
                the credential's domain as it would anywhere; the name
                resolves to the host, whose proxy ends the tls with a
                certificate the vm trusts, injects the credential and sends
                the request on. the value never enters the vm.
              '';
            };

          };
        }
      )
    );
  };
}
