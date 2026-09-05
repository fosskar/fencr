# nixos module and flakelet module

fencr ships two consumption surfaces: a NixOS module (`nixosModules.fencr`)
and a [flakelet](https://github.com/Mic92/flakelet) module
(`flakelets.default`).

## why both

The NixOS module is the native surface: the sandbox is part of the host
configuration, rebuilt and rolled back with it.

The flakelet surface exists for the update cadence. A sandbox plus the agent
inside it moves much faster than a host: with flakelet the host only declares
the flake, and `flakelet update` (or its timer) rolls the sandbox forward —
new agent, new guest image, same host generation. Rollback and health checks
come from flakelet.

## constraint that shapes the flakelet variant

A flakelet `impl` returns systemd units only — no networkd, no nftables
options, no `boot.kernelModules`, no users. The host-level plumbing the
NixOS module expresses declaratively must become unit payloads:

- bridge, addressing and nat/seal nftables rules: oneshot setup unit running
  `ip` and `nft`, torn down in `ExecStop`
- `vhost_vsock`: `ExecStartPre` modprobe
- the microvm itself: the microvm.nix runner script as the main unit; the
  guest NixOS system evaluates against fencr's own pinned inputs, not the
  host's nixpkgs
- forwards: socket units, which flakelet supports natively

Both surfaces must derive from one shared core (per-instance naming, subnet,
cid, firewall ruleset) so the seal semantics cannot drift between them.

## consequences

- the shared core is generated data (ruleset text, unit fragments), not
  NixOS option merging, so both frontends can consume it
- the flakelet variant needs the host to have kvm and vsock available;
  it asserts at activation rather than configuring the host
