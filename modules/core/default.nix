# the builders behind the nixos module, one file per concern: instance
# derivation, hardening sets, the hypervisor unit, forward transports, the
# egress proxy and seal, the credential proxies, the host unit set and the
# guest system. pure functions of an instance, so checks/core.nix probes
# them without a host. every part sees the whole through `core`
{ lib }:
lib.fix (
  core:
  lib.foldl' (parts: part: parts // import part { inherit lib core; }) { } [
    ./instance.nix
    ./hardening.nix
    ./vm.nix
    ./forwards.nix
    ./egress.nix
    ./credentials.nix
    ./host-units.nix
    ./guest.nix
  ]
)
