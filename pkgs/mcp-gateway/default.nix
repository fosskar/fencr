{ lib, buildGoModule }:
buildGoModule {
  pname = "fencr-mcp-gateway";
  version = "0";
  src = ./.;
  vendorHash = "sha256-NbuvbsmNbz3aKdjyyfpkbi52yRhXl473j3LvAUDn3L8=";
  env.CGO_ENABLED = 0;
  meta = {
    description = "Host MCP gateway with per-sandbox permissions";
    license = lib.licenses.mit;
    mainProgram = "fencr-mcp-gateway";
  };
}
