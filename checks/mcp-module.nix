self: pkgs:
let
  inherit (pkgs) lib;
  evaluate =
    extra:
    (self.inputs.nixpkgs.lib.nixosSystem {
      inherit pkgs;
      modules = [
        self.nixosModules.fencr
        {
          networking.useNetworkd = true;
          system.stateVersion = "26.11";
          fencr.mcpGateway = {
            enable = true;
            servers.calendar = {
              url = "http://127.0.0.1:8765/mcp/";
              tokenFile = "/run/secrets/calendar";
            };
            servers.time.command = [
              "/bin/mcp-time"
              "--format"
              "%H:%M"
            ];
          };
          fencr.sandboxes.agent.mcp.enable = true;
          fencr.sandboxes.reader.mcp = {
            enable = true;
            allow = [ "calendar.read" ];
          };
        }
        extra
      ];
    }).config;
  config = evaluate { };
  errors =
    config:
    map (entry: entry.message) (
      lib.filter (entry: !entry.assertion && lib.hasPrefix "fencr" entry.message) config.assertions
    );
  credential = config.fencr.credentials.mcp-agent;
  gateway = config.systemd.services.fencr-mcp-gateway;
  timeSocket = config.systemd.sockets.fencr-mcp-backend-time;
  timeService = config.systemd.services."fencr-mcp-backend-time@";
in
assert errors config == [ ];
assert lib.any (entry: !entry.assertion && lib.hasInfix "mcpGateway.approvalMode" entry.message)
  (evaluate { fencr.mcpGateway.approvalMode = "client"; }).assertions;
assert config.fencr.sandboxes.agent.credentials == [ "mcp-agent" ];
assert config.fencr.sandboxes.reader.credentials == [ "mcp-reader" ];
assert config.fencr.sandboxes.agent.mcp.allow == [ ];
assert credential.domain == "mcp.fencr" && !credential.substitutePlaceholder;
assert credential.allow == [ "* /mcp/" ];
assert !(config.fencr.guestSystems.agent.config.environment.sessionVariables ? MCP_GATEWAY_TOKEN);
assert lib.elem "fencr-mcp-gateway.socket" config.systemd.services.fencr-agent-egress.requires;
assert config.systemd.sockets.fencr-mcp-gateway.listenStreams == [ "127.0.0.1:8764" ];
assert lib.elem "fencr-mcp-tokens.service" gateway.requires;
assert lib.elem "d /var/lib/fencr-mcp 0700 root root -" config.systemd.tmpfiles.rules;
assert gateway.serviceConfig.IPAddressDeny == "any";
assert gateway.serviceConfig.IPAddressAllow == [ "127.0.0.1/32" ];
assert
  gateway.serviceConfig.LoadCredential == [
    "principal-agent:/var/lib/fencr-mcp/agent"
    "principal-reader:/var/lib/fencr-mcp/reader"
    "backend-calendar:/run/secrets/calendar"
  ];
assert lib.elem "fencr-mcp-backend-time.socket" gateway.requires;
assert lib.elem "fencr-mcp-backend-time.socket" gateway.after;
assert gateway.serviceConfig.SupplementaryGroups == [ "fencr-mcp" ];
assert config.users.groups ? fencr-mcp;
assert timeSocket.listenStreams == [ "/run/fencr-mcp/time.sock" ];
assert
  timeSocket.socketConfig.Accept
  && timeSocket.socketConfig.SocketGroup == "fencr-mcp"
  && timeSocket.socketConfig.SocketMode == "0660";
assert timeService.serviceConfig.ExecStart == ''"/bin/mcp-time" "--format" "%%H:%%M"'';
assert timeService.serviceConfig.DynamicUser;
assert !(timeService.serviceConfig ? LoadCredential);
assert
  timeService.serviceConfig.StandardInput == "socket"
  && timeService.serviceConfig.StandardOutput == "socket";
assert
  errors (evaluate {
    fencr.mcpGateway.servers.calendar.command = [ "/bin/calendar" ];
  }) != [ ];
# a sandbox's derived names may not land on the gateway's or a backend's
assert lib.elem
  "fencr: sandbox mcp-gateway and the MCP gateway derive fencr-mcp-gateway; rename one."
  (
    errors (evaluate {
      fencr.sandboxes.mcp-gateway.id = 7;
    })
  );
assert lib.elem
  "fencr: sandbox mcp-backend and MCP server egress derive fencr-mcp-backend-egress; rename one."
  (
    errors (evaluate {
      fencr.sandboxes.mcp-backend.id = 7;
      fencr.mcpGateway.servers.egress.command = [ "/bin/egress" ];
    })
  );
assert
  errors (evaluate {
    fencr.mcpGateway.servers.time.command = lib.mkForce [ "mcp-time" ];
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.servers.time.tokenFile = "/run/secrets/time";
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.servers.calendar.tokenFile = lib.mkForce null;
  }) != [ ];
assert
  errors (evaluate {
    fencr.sandboxes.agent.credentials = [ "mcp-reader" ];
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.enable = lib.mkForce false;
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.servers.calendar.url = lib.mkForce "http://192.168.1.2:8765/mcp/";
  }) != [ ];
pkgs.runCommand "fencr-mcp-module" { } ''
  ${pkgs.python3}/bin/python3 - <<'PY'
  import json
  from pathlib import Path
  config = json.loads(Path("${gateway.environment.MCP_GATEWAY_CONFIG}").read_text())
  assert config["principals"]["agent"]["allow"] == []
  assert config["principals"]["reader"]["allow"] == ["calendar.read"]
  assert config["servers"]["calendar"]["token_credential"] == "backend-calendar"
  assert config["servers"]["time"] == {"socket": "/run/fencr-mcp/time.sock", "hidden_tools": []}
  assert "approval_mode" not in config
  PY
  touch "$out"
''
