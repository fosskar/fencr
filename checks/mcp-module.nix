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
          };
          fencr.vms.agent.mcp.enable = true;
          fencr.vms.reader.mcp = {
            enable = true;
            allow = [ "calendar.read" ];
          };
        }
        extra
      ];
    }).config;
  config = evaluate { };
  clientConfig = evaluate { fencr.mcpGateway.approvalMode = "client"; };
  errors =
    config:
    map (entry: entry.message) (
      lib.filter (entry: !entry.assertion && lib.hasPrefix "fencr" entry.message) config.assertions
    );
  credential = config.fencr.credentials.mcp-agent;
  gateway = config.systemd.services.fencr-mcp-gateway;
in
assert errors config == [ ];
assert config.fencr.mcpGateway.approvalMode == "host";
assert errors clientConfig == [ ];
assert lib.any (warning: lib.hasInfix "compromised guest/client" warning) clientConfig.warnings;
assert
  errors (evaluate {
    fencr.mcpGateway.approvalMode = "client";
    fencr.mcpGateway.approvalCommand = [ "/bin/true" ];
  }) != [ ];
assert config.fencr.vms.agent.credentials == [ "mcp-agent" ];
assert config.fencr.vms.reader.credentials == [ "mcp-reader" ];
assert config.fencr.vms.agent.mcp.allow == [ ];
assert config.fencr.mcpGateway.servers.calendar.approvalTools == [ "*" ];
assert credential.domain == "mcp.fencr" && !credential.substitutePlaceholder;
assert credential.allow == [ "GET,POST,DELETE /mcp/" ];
assert !(config.fencr.guestSystems.agent.config.environment.sessionVariables ? MCP_GATEWAY_TOKEN);
assert lib.elem "fencr-mcp-gateway.service" config.systemd.services.fencr-agent-egress.requires;
assert lib.elem "fencr-mcp-tokens.service" gateway.requires;
assert gateway.serviceConfig.IPAddressDeny == "any";
assert gateway.serviceConfig.IPAddressAllow == [ "127.0.0.1/32" ];
assert
  gateway.serviceConfig.LoadCredential == [
    "principal-agent:/var/lib/fencr-mcp/agent"
    "principal-reader:/var/lib/fencr-mcp/reader"
    "backend-calendar:/run/secrets/calendar"
  ];
assert
  errors (evaluate {
    fencr.vms.agent.credentials = [ "mcp-reader" ];
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.enable = lib.mkForce false;
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.servers.calendar.url = lib.mkForce "http://192.168.1.2:8765/mcp/";
  }) != [ ];
assert
  errors (evaluate {
    fencr.mcpGateway.approvalCommand = [ "relative-command" ];
  }) != [ ];
pkgs.runCommand "fencr-mcp-module" { } ''
  ${pkgs.python3}/bin/python3 - <<'PY'
  import json
  from pathlib import Path
  config = json.loads(Path("${gateway.environment.MCP_GATEWAY_CONFIG}").read_text())
  assert config["principals"]["agent"]["allow"] == []
  assert config["principals"]["reader"]["allow"] == ["calendar.read"]
  assert config["servers"]["calendar"]["approval_tools"] == ["*"]
  assert config["servers"]["calendar"]["token_credential"] == "backend-calendar"
  assert config["approval_command"] == []
  assert config["approval_mode"] == "host"
  client = json.loads(Path("${clientConfig.systemd.services.fencr-mcp-gateway.environment.MCP_GATEWAY_CONFIG}").read_text())
  assert client["approval_mode"] == "client"
  PY
  touch "$out"
''
