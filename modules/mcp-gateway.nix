{
  config,
  lib,
  pkgs,
  ...
}:
let
  core = import ./core { inherit lib; };
  cfg = config.fencr.mcpGateway;
  members = lib.filterAttrs (_: vm: vm.mcp.enable) config.fencr.vms;
  credentialName = name: "mcp-${name}";
  tokenPath = name: "/var/lib/fencr-mcp/${name}";
  gateway = pkgs.callPackage ../pkgs/mcp-gateway { };
  backendUnits = lib.filter (unit: unit != null) (
    lib.mapAttrsToList (_: server: server.service) cfg.servers
  );
  gatewayConfig = pkgs.writeText "fencr-mcp-gateway.json" (
    builtins.toJSON {
      inherit (cfg) port;
      approval_mode = cfg.approvalMode;
      approval_command = cfg.approvalCommand;
      approval_timeout = cfg.approvalTimeout;
      servers = lib.mapAttrs (name: server: {
        inherit (server) url;
        token_credential = "backend-${name}";
        approval_tools = server.approvalTools;
        hidden_tools = server.hiddenTools;
      }) cfg.servers;
      principals = lib.mapAttrs (name: vm: {
        inherit (vm.mcp) allow;
        token_credential = "principal-${name}";
      }) members;
    }
  );
in
{
  options.fencr.mcpGateway = {
    enable = lib.mkEnableOption "the host-side MCP gateway";
    port = lib.mkOption {
      type = lib.types.port;
      default = 8764;
      description = "host loopback port for the gateway; never opened to guests directly.";
    };
    approvalMode = lib.mkOption {
      type = lib.types.enum [
        "host"
        "client"
      ];
      default = "host";
      description = ''
        host requires approvalCommand to approve protected calls independently
        of the guest. client sends MCP form elicitation to the requesting client,
        which may display it in the same chat. client mode trusts that client to
        obtain human approval; a compromised client can approve its own calls.
        refusal, unsupported elicitation and timeout deny the call in either case.
      '';
    };
    approvalCommand = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        trusted host command receiving one JSON object on stdin with principal,
        server, tool and full arguments. exit 0 approves this invocation only;
        nonzero, timeout or no command denies it. it must obtain approval outside
        the guest, not ask the requesting MCP client. runs as the gateway's
        isolated user with a minimal environment, no login session and loopback
        network access only. stdout is ignored; stderr goes to the journal.
        use absolute paths.
      '';
    };
    approvalTimeout = lib.mkOption {
      type = lib.types.ints.positive;
      default = 120;
      description = "seconds to wait for approval in either mode before denying the call.";
    };
    servers = lib.mkOption {
      default = { };
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            url = lib.mkOption {
              type = lib.types.str;
              example = "http://127.0.0.1:8765/mcp/";
              description = "streamable HTTP backend on host IPv4 loopback; it must bind only to loopback and require its token.";
            };
            tokenFile = lib.mkOption {
              type = lib.types.path;
              description = "host file containing the backend's bare bearer token, never granted to a VM.";
            };
            service = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "calendar-mcp.service";
              description = "optional backend systemd unit required by the gateway.";
            };
            approvalTools = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "*" ];
              description = "tool-name globs requiring approval through approvalMode. all tools by default; explicitly exclude only tools safe to call without approval.";
            };
            hiddenTools = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "tool-name globs neither listed nor callable by any VM.";
            };
          };
        }
      );
      description = "explicit MCP backends; backend services and their secrets remain host configuration.";
    };
  };

  options.fencr.vms = lib.mkOption {
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
              description = "<server>.<tool> globs this VM may list and call; empty grants nothing. application-side MCP settings remain the payload's responsibility.";
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
          message = "fencr: VM MCP access requires fencr.mcpGateway.enable.";
        }
      ];
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.servers != { } && members != { };
          message = "fencr.mcpGateway requires explicit servers and at least one VM with mcp.enable.";
        }
        {
          assertion = lib.all (
            name: builtins.match "[A-Za-z0-9_-]+" name != null && !(lib.hasInfix "__" name)
          ) (builtins.attrNames cfg.servers ++ builtins.attrNames members);
          message = "fencr.mcpGateway server and VM names must use letters, digits, hyphens or underscores, without double underscores.";
        }
        {
          assertion = lib.all (
            server: builtins.match "http://127[.]0[.]0[.]1:[0-9]+/[^?#]*" server.url != null
          ) (lib.attrValues cfg.servers);
          message = "fencr.mcpGateway backends must use explicit http://127.0.0.1:<port>/<path> URLs.";
        }
        {
          assertion = cfg.approvalCommand == [ ] || lib.hasPrefix "/" (lib.head cfg.approvalCommand);
          message = "fencr.mcpGateway.approvalCommand must name an absolute executable path.";
        }
        {
          assertion = cfg.approvalMode != "client" || cfg.approvalCommand == [ ];
          message = "fencr.mcpGateway: approvalCommand is only used with approvalMode = host; remove it to select client approval.";
        }
      ]
      ++ lib.mapAttrsToList (name: vm: {
        assertion = lib.all (other: other == name || !(lib.elem (credentialName other) vm.credentials)) (
          builtins.attrNames members
        );
        message = "fencr: ${name} may not borrow another VM's MCP credential.";
      }) config.fencr.vms;

      fencr.credentials = lib.mapAttrs' (
        name: _:
        lib.nameValuePair (credentialName name) {
          upstream = "http://127.0.0.1:${toString cfg.port}";
          domain = "mcp.fencr";
          secretFile = tokenPath name;
          substitutePlaceholder = false;
          allow = [ "GET,POST,DELETE /mcp/" ];
        }
      ) members;

      systemd.services = {
        fencr-mcp-tokens = {
          description = "create per-VM MCP gateway credentials";
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

              for name in ${builtins.toJSON (builtins.attrNames members)}:
                  path = Path("/var/lib/fencr-mcp") / name
                  if not path.exists():
                      descriptor, temporary = tempfile.mkstemp(dir=path.parent)
                      with os.fdopen(descriptor, "w") as output:
                          output.write("Bearer " + secrets.token_hex(32))
                      os.replace(temporary, path)
            ''}";
          };
        };
        fencr-mcp-gateway = {
          description = "per-VM MCP gateway";
          wantedBy = [ "multi-user.target" ];
          requires = [ "fencr-mcp-tokens.service" ] ++ backendUnits;
          after = [ "fencr-mcp-tokens.service" ] ++ backendUnits;
          environment.MCP_GATEWAY_CONFIG = gatewayConfig;
          serviceConfig = core.hardened // {
            DynamicUser = true;
            ExecStart = lib.getExe gateway;
            Restart = "on-failure";
            IPAddressDeny = "any";
            IPAddressAllow = [ "127.0.0.1/32" ];
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_UNIX"
            ];
            LoadCredential =
              lib.mapAttrsToList (name: _: "principal-${name}:${tokenPath name}") members
              ++ lib.mapAttrsToList (name: server: "backend-${name}:${server.tokenFile}") cfg.servers;
          };
        };
      }
      // lib.mapAttrs' (
        name: _:
        lib.nameValuePair (core.unitsOf name).egress {
          requires = [ "fencr-mcp-gateway.service" ];
          after = [ "fencr-mcp-gateway.service" ];
        }
      ) members;
    })
  ];
}
