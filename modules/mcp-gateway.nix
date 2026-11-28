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
  # a stdio server some sandbox holds credentials for gets a socket and a
  # backend unit per sandbox instead of the shared ones
  credentialed = lib.unique (
    lib.concatMap (sandbox: lib.attrNames sandbox.mcp.credentials) (lib.attrValues members)
  );
  sharedStdio = lib.filterAttrs (name: _: !lib.elem name credentialed) stdioServers;
  perSandbox = lib.concatLists (
    lib.mapAttrsToList (
      sandbox: options:
      lib.mapAttrsToList (server: files: { inherit sandbox server files; }) options.mcp.credentials
    ) members
  );
  sandboxUnit = server: sandbox: "${stdioUnit server}-${sandbox}";
  sandboxSocket = server: sandbox: "/run/fencr-mcp/${server}/${sandbox}.sock";
  # the gateway's `reachable`: a glob before the first dot reaches every server
  reaches =
    allow: server:
    lib.any (
      pattern:
      let
        head = lib.head (lib.splitString "." pattern);
      in
      builtins.match ".*[*?[].*" head != null || (lib.hasInfix "." pattern && head == server)
    ) allow;
  backendSocket = description: path: {
    inherit description;
    listenStreams = [ path ];
    socketConfig = {
      Accept = true;
      SocketGroup = "fencr-mcp";
      SocketMode = "0660";
    };
  };
  backendUnits =
    lib.filter (unit: unit != null) (lib.mapAttrsToList (_: server: server.service) cfg.servers)
    ++ lib.mapAttrsToList (name: _: "${stdioUnit name}.socket") sharedStdio
    ++ map ({ sandbox, server, ... }: "${sandboxUnit server sandbox}.socket") perSandbox;
  gatewayConfig = pkgs.writeText "fencr-mcp-gateway.json" (
    builtins.toJSON {
      servers = lib.mapAttrs (
        name: server:
        {
          hidden_tools = server.hiddenTools;
        }
        // (
          if server.command != null then
            lib.optionalAttrs (!lib.elem name credentialed) { socket = stdioSocket name; }
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
        backend_sockets = lib.mapAttrs (server: _: sandboxSocket server name) sandbox.mcp.credentials;
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
                tokens and reaches only outbound; give it credentials and other
                settings through systemd.services."fencr-mcp-backend-<name>@".
                set this or url. once a sandbox sets mcp.credentials.<name>, every
                sandbox that reaches it must, and each gets
                fencr-mcp-backend-<name>-<sandbox>@.service with that unit's
                environment, path and serviceConfig plus its own files.
              '';
            };
            outbound = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "192.168.1.5/32" ];
              description = "addresses or CIDRs, as IPAddressAllow takes them, the command backend may reach; a non-empty list also grants systemd-resolved's stub. empty means no network.";
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
          credentials = lib.mkOption {
            type = lib.types.attrsOf (lib.types.attrsOf lib.types.path);
            default = { };
            example = {
              calendar.password = "/run/secrets/calendar-agent";
            };
            description = "host files per command server, loaded as systemd credentials into this sandbox's own backend unit for that server and no other.";
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
      ]
      ++ lib.mapAttrsToList (name: sandbox: {
        assertion = sandbox.mcp.enable || sandbox.mcp.credentials == { };
        message = "fencr: sandbox ${name} sets mcp.credentials without mcp.enable.";
      }) config.fencr.sandboxes;
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
            builtins.match "http://127[.]0[.]0[.]1:[0-9]+/[^?#]*" server.url != null
            && server.tokenFile != null
            && server.outbound == [ ]
          ) (lib.attrValues httpServers);
          message = "fencr.mcpGateway url backends must use explicit http://127.0.0.1:<port>/<path> URLs and a tokenFile, and take no outbound.";
        }
        {
          assertion = lib.all (
            server: lib.hasPrefix "/" (lib.head server.command) && server.tokenFile == null
          ) (lib.attrValues stdioServers);
          message = "fencr.mcpGateway command backends must name an absolute executable and take no tokenFile.";
        }
        {
          assertion = lib.all (server: stdioServers ? ${server}) credentialed;
          message = "fencr: mcp.credentials must name fencr.mcpGateway command backends.";
        }
        {
          assertion = lib.all (
            { files, ... }: lib.all (name: builtins.match "[A-Za-z0-9_-]+" name != null) (lib.attrNames files)
          ) perSandbox;
          message = "fencr: mcp.credentials names must use letters, digits, hyphens or underscores.";
        }
      ]
      ++ lib.concatLists (
        lib.mapAttrsToList (
          sandbox: options:
          map (server: {
            assertion = !(reaches options.mcp.allow server) || options.mcp.credentials ? ${server};
            message = "fencr: sandbox ${sandbox} reaches MCP server ${server}, which has per-sandbox credentials; set fencr.sandboxes.${sandbox}.mcp.credentials.${server}.";
          }) credentialed
        ) members
      );

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
        name: _: lib.nameValuePair (stdioUnit name) (backendSocket "MCP backend ${name}" (stdioSocket name))
      ) sharedStdio
      // lib.listToAttrs (
        map (
          { sandbox, server, ... }:
          lib.nameValuePair (sandboxUnit server sandbox) (
            backendSocket "MCP backend ${server} for ${sandbox}" (sandboxSocket server sandbox)
          )
        ) perSandbox
      );

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
            IPAddressDeny = "any";
            IPAddressAllow = lib.optionals (server.outbound != [ ]) ([ "127.0.0.53/32" ] ++ server.outbound);
            RestrictAddressFamilies = [
              "AF_UNIX"
            ]
            ++ lib.optionals (server.outbound != [ ]) [
              "AF_INET"
              "AF_INET6"
            ];
          };
        }
      ) stdioServers
      // lib.listToAttrs (
        map (
          {
            sandbox,
            server,
            files,
          }:
          let
            shared = config.systemd.services."${stdioUnit server}@";
          in
          lib.nameValuePair "${sandboxUnit server sandbox}@" {
            description = "MCP backend ${server} for ${sandbox}";
            # the unit derives PATH from path itself; a copied one would conflict
            environment = removeAttrs shared.environment [ "PATH" ];
            inherit (shared) path;
            serviceConfig = shared.serviceConfig // {
              LoadCredential =
                lib.toList (shared.serviceConfig.LoadCredential or [ ])
                ++ lib.mapAttrsToList (name: file: "${name}:${file}") files;
            };
          }
        ) perSandbox
      );
    })
  ];
}
