{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  core = import ./core { inherit lib; };
  cfg = config.fencr.mcpGateway;
  members = lib.filterAttrs (_: sandbox: sandbox.mcp.enable) config.fencr.sandboxes;
  # firecracker delivers the guest's vsock port to this path, in the run
  # directory only the sandbox's user enters, so the path names the sandbox
  socketOf = name: "${core.vsockOf name}_${toString core.mcpPort}";
  gateway = pkgs.callPackage ../pkgs/mcp-gateway { };
  httpServers = lib.filterAttrs (_: server: server.url != null) cfg.servers;
  stdioServers = lib.filterAttrs (_: server: server.command != null) cfg.servers;
  # the prefix keeps these units and the dynamic user systemd derives from
  # them apart from the gateway's own units
  stdioUnit = name: "fencr-mcp-backend-${name}";
  stdioSocket = name: "/run/fencr-mcp/${name}.sock";
  backendUnits =
    lib.filter (unit: unit != null) (lib.mapAttrsToList (_: server: server.service) cfg.servers)
    ++ lib.mapAttrsToList (name: _: "${stdioUnit name}.socket") stdioServers;
  gatewayConfig = pkgs.writeText "fencr-mcp-gateway.json" (
    builtins.toJSON {
      servers = lib.mapAttrs (
        name: server:
        {
          hidden_tools = server.hiddenTools;
        }
        // (
          if server.command != null then
            { socket = stdioSocket name; }
          else
            {
              inherit (server) url;
              token_credential = "backend-${name}";
            }
        )
      ) cfg.servers;
      principals = lib.mapAttrs (name: sandbox: {
        inherit (sandbox.mcp) allow;
        socket = socketOf name;
      }) members;
    }
  );
in
{
  imports =
    map
      (
        option:
        lib.mkRemovedOptionModule
          [
            "fencr"
            "mcpGateway"
            option
          ]
          "the MCP gateway no longer asks for approval; mcp.allow and hiddenTools decide what a sandbox may call."
      )
      [
        "approvalMode"
        "approvalCommand"
        "approvalTimeout"
      ];

  options.fencr.mcpGateway = {
    enable = lib.mkEnableOption "the host-side MCP gateway";
    port = lib.mkOption {
      type = lib.types.port;
      default = 8764;
      description = "guest loopback port where an mcp-enabled sandbox reaches the gateway, as http://127.0.0.1:<port>/mcp/; the guest forwards it over vsock.";
    };
    servers = lib.mkOption {
      default = { };
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            url = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "http://127.0.0.1:8765/mcp/";
              description = "streamable HTTP backend on host IPv4 loopback; it must bind only to loopback and require its token. set this or command.";
            };
            tokenFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "host file containing the url backend's bare bearer token, never granted to a sandbox.";
            };
            command = lib.mkOption {
              type = lib.types.nullOr (lib.types.nonEmptyListOf lib.types.str);
              default = null;
              example = [
                "/run/current-system/sw/bin/mcp-server-time"
              ];
              description = ''
                stdio backend: an absolute executable and its arguments. systemd
                runs it as fencr-mcp-backend-<name>@.service, one process per
                sandbox session, with the connection from the gateway as its stdin
                and stdout, under its own dynamic user. it cannot read the gateway's
                tokens; give it credentials, network limits and other settings
                through systemd.services."fencr-mcp-backend-<name>@". set this or url.
              '';
            };
            service = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "calendar-mcp.service";
              description = "optional backend systemd unit required by the gateway.";
            };
            hiddenTools = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "tool-name globs neither listed nor callable by any sandbox.";
            };
          };
        }
      );
      description = "explicit MCP backends; backend services and their secrets remain host configuration.";
    };
  };

  options.fencr.sandboxes = lib.mkOption {
    type = lib.types.attrsOf (
      lib.types.submodule {
        options.mcp = {
          enable = lib.mkEnableOption "access to the host MCP gateway at http://127.0.0.1:<fencr.mcpGateway.port>/mcp/ in the guest";
          allow = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            example = [ "calendar.list_events" ];
            description = "<server>.<tool> globs this sandbox may list and call; empty grants nothing. application-side MCP settings remain the payload's responsibility.";
          };
        };
      }
    );
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = members == { } || cfg.enable;
          message = "fencr: sandbox MCP access requires fencr.mcpGateway.enable.";
        }
      ];
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.servers != { } && members != { };
          message = "fencr.mcpGateway requires explicit servers and at least one sandbox with mcp.enable.";
        }
        {
          # a sandbox name is already narrower than this, from resolveInstance.
          # "__" separates <server>__<tool>, so only the server half can
          # carry it into a name a client has to split again
          assertion = lib.all (
            name: builtins.match "[A-Za-z0-9_-]+" name != null && !(lib.hasInfix "__" name)
          ) (builtins.attrNames cfg.servers);
          message = "fencr.mcpGateway server names must use letters, digits, hyphens or underscores, without double underscores.";
        }
        {
          assertion = lib.all (server: (server.url == null) != (server.command == null)) (
            lib.attrValues cfg.servers
          );
          message = "fencr.mcpGateway backends must set exactly one of url and command.";
        }
        {
          assertion = lib.all (
            server:
            builtins.match "http://127[.]0[.]0[.]1:[0-9]+/[^?#]*" server.url != null && server.tokenFile != null
          ) (lib.attrValues httpServers);
          message = "fencr.mcpGateway url backends must use explicit http://127.0.0.1:<port>/<path> URLs and a tokenFile.";
        }
        {
          assertion = lib.all (
            server: lib.hasPrefix "/" (lib.head server.command) && server.tokenFile == null
          ) (lib.attrValues stdioServers);
          message = "fencr.mcpGateway command backends must name an absolute executable and take no tokenFile.";
        }
      ];

      users.groups.fencr-mcp = { };
      # pid 1 holds each sandbox's socket while the gateway restarts. 0666 and
      # no SocketUser, as with the trust and secrets relays: the run
      # directory's 0700 keeps other users off it. pid 1 holds the stdio
      # backends' sockets too, in a directory only it writes, so the chown to
      # the group is not a race; only the gateway is in that group
      systemd.sockets = {
        fencr-mcp-gateway = {
          description = "per-sandbox MCP gateway";
          wantedBy = [ "sockets.target" ];
          listenStreams = lib.mapAttrsToList (name: _: socketOf name) members;
          socketConfig.SocketMode = "0666";
        };
      }
      // lib.mapAttrs' (
        name: _:
        lib.nameValuePair (stdioUnit name) {
          description = "MCP backend ${name}";
          listenStreams = [ (stdioSocket name) ];
          socketConfig = {
            Accept = true;
            SocketGroup = "fencr-mcp";
            SocketMode = "0660";
          };
        }
      ) stdioServers;

      systemd.services = {
        fencr-mcp-gateway = {
          description = "per-sandbox MCP gateway";
          wantedBy = [ "multi-user.target" ];
          requires = [ "fencr-mcp-gateway.socket" ] ++ backendUnits;
          after = [ "fencr-mcp-gateway.socket" ] ++ backendUnits;
          environment.MCP_GATEWAY_CONFIG = gatewayConfig;
          serviceConfig = core.hardened // {
            DynamicUser = true;
            SupplementaryGroups = [ "fencr-mcp" ];
            ExecStart = lib.getExe gateway;
            Restart = "on-failure";
            # every mcp-enabled sandbox drives this one process
            MemoryMax = "512M";
            # url backends are on host loopback; sandboxes arrive on unix sockets
            IPAddressDeny = "any";
            IPAddressAllow = [ "127.0.0.1/32" ];
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_UNIX"
            ];
            LoadCredential = lib.mapAttrsToList (
              name: server: "backend-${name}:${server.tokenFile}"
            ) httpServers;
          };
        };
      }
      // lib.mapAttrs' (
        name: server:
        lib.nameValuePair "${stdioUnit name}@" {
          description = "MCP backend ${name}";
          serviceConfig = core.hardened // {
            DynamicUser = true;
            ExecStart = utils.escapeSystemdExecArgs server.command;
            StandardInput = "socket";
            StandardOutput = "socket";
            StandardError = "journal";
          };
        }
      ) stdioServers;
    })
  ];
}
