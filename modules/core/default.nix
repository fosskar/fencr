# the builders behind the nixos module: pure functions of an instance, so
# checks/core.nix probes them without a host. every part sees the whole
# through `core`
{ lib }:
lib.fix (
  core:
  lib.foldl' (parts: part: parts // import part { inherit lib core; }) { } [
    ./instance.nix
    ./hardening.nix
    ./vm.nix
    ./egress.nix
    ./firewall.nix
    ./credentials.nix
    ./checkpoint.nix
    ./host-units.nix
    ./guest.nix
  ]
)
