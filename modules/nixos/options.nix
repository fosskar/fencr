# the options of fencr: what a host declares, what a vm may be given
{ lib, ... }@host:
let
  core = import ../core { inherit lib; };
  exposeType = lib.types.coercedTo lib.types.str core.parseExpose lib.types.port;
  destinationType = lib.types.coercedTo lib.types.str core.parseDestination (
    lib.types.submodule {
      options = {
        address = lib.mkOption { type = lib.types.str; };
        port = lib.mkOption { type = lib.types.port; };
      };
    }
  );
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
      lib.types.submodule {
        options = {
          upstream = lib.mkOption {
            type = lib.types.str;
            example = "https://api.anthropic.com";
            description = ''
              where requests go, with the credential injected: a public
              https api or a plain http port on host loopback. private
              ranges are refused.
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
            description = "host file with the raw header value, for example \"Bearer x\"; never enters a vm.";
          };
        };
      }
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
        { config, ... }:
        {
          options = {
            id = lib.mkOption {
              type = lib.types.ints.between 0 8;
              description = "unique instance index; derives bridge, subnet, tap, mac and vsock cid.";
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
              description = "the host's address on the vm's bridge, where hostPorts answer.";
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
              description = "guest memory ceiling; free page reporting returns unused memory to the host.";
            };
            memoryMax = lib.mkOption {
              type = lib.types.str;
              default = core.defaults.memoryMax;
              description = "hard cap on the whole vm unit, enforced by the host; guest ceiling plus hypervisor overhead.";
            };
            stateSize = lib.mkOption {
              type = lib.types.int;
              default = core.defaults.stateSize;
              description = ''
                size in MiB of the vm's /var/lib, a sparse disk image at
                /var/lib/fencr-vms/<name>/state.img. a larger value grows the
                image and its filesystem on the next start; it never shrinks.
              '';
            };
            cpuQuota = lib.mkOption {
              type = lib.types.str;
              default = core.defaults.cpuQuota;
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

            egress = lib.mkOption {
              type = lib.types.enum [
                "open"
                "closed"
              ];
              default = core.defaults.egress;
              description = ''
                "open": internet and dns reachable, private ranges sealed.
                "closed": nothing reachable beyond allowedTCPDestinations,
                dns included. this is the default.
              '';
            };

            allowedDomains = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = core.defaults.allowedDomains;
              example = lib.literalExpression ''[ "github.com" "*.github.com" ]'';
              description = ''
                domains reachable over tls; "*.github.com" does not match the
                bare "github.com", list both. implies egress = "closed": the
                vm resolves every name to the host, which reads the server
                name from the tls handshake and passes allowed connections
                through unread. no proxy variables, no interception, and no
                dns leaves the host.
              '';
            };

            allowedTCPDestinations = lib.mkOption {
              type = lib.types.listOf destinationType;
              default = core.defaults.allowedTCPDestinations;
              description = ''
                IPv4 TCP destinations reachable from the vm, as
                "<address>:<port>" or { address; port; }. each entry is an
                explicit exception to the default closed egress policy.
              '';
            };

            expose = lib.mkOption {
              type = lib.types.listOf exposeType;
              default = core.defaults.expose;
              example = [ 9119 ];
              description = ''
                guest ports the host may reach, at the vm's address on its
                bridge. the service inside must listen on that address, not
                on loopback. nothing on the host reaches any other guest port.
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

            hostPorts = lib.mkOption {
              type = lib.types.listOf lib.types.port;
              default = core.defaults.hostPorts;
              description = "host TCP ports reachable from the vm over the bridge.";
            };

            dns = lib.mkOption {
              type = lib.types.str;
              default = builtins.head host.config.networking.nameservers;
              defaultText = "the host's first resolver";
            };
          };
        }
      )
    );
  };
}
