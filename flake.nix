{
  description = "fencr — sealed microVM sandboxes for AI agents, as NixOS options";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixbot = {
      url = "github:Mic92/nixbot";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.treefmt-nix.follows = "treefmt-nix";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixbot,
      treefmt-nix,
      ...
    }@inputs:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      treefmtFor = forAllSystems (pkgs: treefmt-nix.lib.evalModule pkgs ./treefmt.nix);
    in
    {
      nixosModules = {
        fencr = import ./modules/nixos { inherit inputs; };
        default = self.nixosModules.fencr;
      };

      # nixbot scheduled effects: flake input updates.
      herculesCI = import ./effects.nix {
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
        inherit nixbot;
      };

      checks = forAllSystems (pkgs: {
        formatting = treefmtFor.${pkgs.stdenv.hostPlatform.system}.config.build.check self;

        nixos-module =
          (nixpkgs.lib.nixosSystem {
            modules = [ (import ./checks/nixos-module.nix self pkgs.stdenv.hostPlatform.system) ];
          }).config.system.build.toplevel;

        core = import ./checks/core.nix self pkgs;

        cli = import ./checks/cli.nix self pkgs;

        nixos-boot = import ./checks/nixos-boot.nix self pkgs;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            treefmtFor.${pkgs.stdenv.hostPlatform.system}.config.build.wrapper
          ];
        };
      });

      formatter = forAllSystems (
        pkgs: treefmtFor.${pkgs.stdenv.hostPlatform.system}.config.build.wrapper
      );
    };
}
