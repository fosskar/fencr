{ pkgs, ... }:
{
  projectRootFile = "flake.nix";

  programs = {
    nixfmt.enable = true;
    deadnix.enable = true;
    statix.enable = true;
    mdformat.enable = true;
    rustfmt.enable = true;
    gofmt.enable = true;
    golangci-lint = {
      enable = true;
      # it loads packages through the go tool, which treefmt does not put
      # on the path
      package = pkgs.writeShellScriptBin "golangci-lint" ''
        export PATH=${pkgs.go}/bin:$PATH
        # the proxy is built without cgo; typechecking net with it fails
        export CGO_ENABLED=0
        exec ${pkgs.golangci-lint}/bin/golangci-lint "$@"
      '';
    };
  };
}
