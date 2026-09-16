{
  lib,
  python3,
  runCommand,
  writeShellApplication,
}:
let
  python = python3.withPackages (packages: [ packages.mcp ]);
  gateway = writeShellApplication {
    name = "fencr-mcp-gateway";
    runtimeInputs = [ python ];
    text = ''
      exec python ${./gateway.py}
    '';
    meta = {
      description = "Host MCP gateway with per-VM permissions";
      license = lib.licenses.mit;
      mainProgram = "fencr-mcp-gateway";
    };
  };
in
gateway.overrideAttrs (old: {
  buildCommand = old.buildCommand + ''
    install -Dm444 ${./LICENSE} "$out/share/licenses/fencr-mcp-gateway/LICENSE"
  '';
  passthru = (old.passthru or { }) // {
    tests.contract = runCommand "fencr-mcp-gateway-tests" { nativeBuildInputs = [ python ]; } ''
      cp ${./gateway.py} gateway.py
      cp ${./test_gateway.py} test_gateway.py
      python -m unittest -v test_gateway
      touch "$out"
    '';
  };
})
