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
  credentialName = name: "mcp-${name}";
  tokenPath = name: "/var/lib/fencr-mcp/${name}";
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
        token_credential = "principal-${name}";
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
      description = "host loopback port for the gateway; never opened to guests directly.";
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
      lib.types.submodule (
        { config, name, ... }: {
          config.credentials = lib.mkIf (cfg.enable && config.mcp.enable) [ (credentialName name) ];
          options.mcp = {
            enable = lib.mkEnableOption "access to the host MCP gateway at https://mcp.fencr/mcp/";
            allow = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "calendar.list_events" ];
              description = "<server>.<tool> globs this sandbox may list and call; empty grants nothing. application-side MCP settings remain the payload's responsibility.";
            };
          };
        }
      )
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
      ]
      ++ lib.mapAttrsToList (name: sandbox: {
        assertion = lib.all (
          other: other == name || !(lib.elem (credentialName other) sandbox.credentials)
        ) (builtins.attrNames members);
        message = "fencr: ${name} may not borrow another sandbox's MCP credential.";
      }) config.fencr.sandboxes;

      fencr.credentials = lib.mapAttrs' (
        name: _:
        lib.nameValuePair (credentialName name) {
          upstream = "http://127.0.0.1:${toString cfg.port}";
          domain = "mcp.fencr";
          secretFile = tokenPath name;
          substitutePlaceholder = false;
          # upstream is an origin, so the path is what keeps this token off
          # every other route on that port. the methods are the mcp sdk's to
          # choose and it rejects the rest itself; pinning them here only
          # breaks the transport the day it uses one more
          allow = [ "* /mcp/" ];
        }
      ) members;

      # StateDirectoryMode sets the mode when the directory is created; an
      # existing one keeps whatever it has, and this reasserts it on every
      # activation
      systemd.tmpfiles.rules = [ "d /var/lib/fencr-mcp 0700 root root -" ];

      users.groups.fencr-mcp = { };
      # pid 1 holds the port the egress units send principal tokens to, so no
      # host user can take it while the gateway restarts. it holds the stdio
      # backends' sockets too, in a directory only it writes, so the chown to
      # the group is not a race; only the gateway is in that group
      systemd.sockets = {
        fencr-mcp-gateway = {
          description = "per-sandbox MCP gateway";
          wantedBy = [ "sockets.target" ];
          listenStreams = [ "127.0.0.1:${toString cfg.port}" ];
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
        fencr-mcp-tokens = {
          description = "create per-sandbox MCP gateway credentials";
          serviceConfig = core.hardened // {
            Type = "oneshot";
            RemainAfterExit = true;
            StateDirectory = "fencr-mcp";
            StateDirectoryMode = "0700";
            ExecStart = "${pkgs.python3}/bin/python3 ${pkgs.writeText "fencr-mcp-tokens.py" ''
              import os
              import secrets
              import tempfile
              from pathlib import Path

              for entry in ${builtins.toJSON (map tokenPath (builtins.attrNames members))}:
                  path = Path(entry)
                  if not path.exists():
                      descriptor, temporary = tempfile.mkstemp(dir=path.parent)
                      with os.fdopen(descriptor, "w") as output:
                          output.write("Bearer " + secrets.token_hex(32))
                      os.replace(temporary, path)
            ''}";
          };
        };
        fencr-mcp-gateway = {
          description = "per-sandbox MCP gateway";
          wantedBy = [ "multi-user.target" ];
          requires = [
            "fencr-mcp-gateway.socket"
            "fencr-mcp-tokens.service"
          ]
          ++ backendUnits;
          after = [
            "fencr-mcp-gateway.socket"
            "fencr-mcp-tokens.service"
          ]
          ++ backendUnits;
          environment.MCP_GATEWAY_CONFIG = gatewayConfig;
          serviceConfig = core.hardened // {
            DynamicUser = true;
            SupplementaryGroups = [ "fencr-mcp" ];
            ExecStart = lib.getExe gateway;
            Restart = "on-failure";
            # every mcp-enabled sandbox drives this one process
            MemoryMax = "512M";
            IPAddressDeny = "any";
            IPAddressAllow = [ "127.0.0.1/32" ];
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_UNIX"
            ];
            LoadCredential =
              lib.mapAttrsToList (name: _: "principal-${name}:${tokenPath name}") members
              ++ lib.mapAttrsToList (name: server: "backend-${name}:${server.tokenFile}") httpServers;
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
      ) stdioServers
      // lib.mapAttrs' (
        name: _:
        lib.nameValuePair (core.unitsOf name).egress {
          requires = [ "fencr-mcp-gateway.socket" ];
          after = [ "fencr-mcp-gateway.socket" ];
        }
      ) members;
    })
  ];
}
