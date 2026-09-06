# instructions

## scope

fencr provides sealed Firecracker microVMs through `nixosModules.fencr` (also
`nixosModules.default`). Payloads are NixOS modules supplied through
`fencr.vms.<name>.services`; fencr ships no agent, repository cloning, or host
working-tree mounts. `nixos-rebuild` is the control plane; the `fencr` CLI does
not mutate host configuration, but `fencr ssh` can run commands as guest root.
Instance and unit tables are compiled into its binary.

Design rationale lives in `docs/decisions/`. Consult the relevant record before
changing a boundary. `hypervisor.md` holds the qemu, crosvm and Firecracker
history and what each move cost. `docs/quickstart.md` and `docs/access.md` describe configuration and SSH access.

## architecture

- `modules/nixos/options.nix` declares the options; `modules/nixos/default.nix`
  composes host networking, systemd units, users, and guest evaluations. Guests
  use the host's `pkgs`; payloads receive the resolved contract through
  `specialArgs.agentSandbox`.
- `modules/core/` holds the pure builders, one file per concern, joined by
  `default.nix` into one fixed point every part sees as `core`: `instance.nix`
  (`defaults`, derived names, `resolveInstance`, `fleetErrors`),
  `hardening.nix` (unit hardening sets, `specialUseNetworks`), `vm.nix`
  (`vmService`), `egress.nix` (egress proxy unit, `firewallOf`),
  `credentials.nix` (the authority and credential proxies), `host-units.nix`
  (`hostUnits`, the secrets socket) and `guest.nix` (`guestBase`). Keep shared
  defaults in `core.defaults` and derivation logic here rather than
  duplicating it in the module or CLI.
- `modules/cli.nix` generates Rust; `modules/core/egress-proxy.rs` answers DNS
  queries, hands credential domains to their proxies by TLS SNI and applies the
  allowlist to the rest. Both use `pkgs.writers.writeRustBin` with Rust edition
  2024, not a Cargo workspace.
- The bridge is the road between host and guest: the guest's sshd and its
  `expose`d ports listen on the guest's address, `fencr.vms.<name>.ip`, and the
  seal's output chain lets the host reach those ports and nothing else. vsock
  carries only the boot-time secrets fetch and the power button: Firecracker's
  unix socket `/run/fencr-<name>/vsock`, in a directory only the VM's user and
  group `kvm` enter, with guest-to-host port N arriving on `vsock_N` beside it.
- Each VM runs as `fencr-<name>` with persistent state at
  `/var/lib/fencr-vms/<name>/state.img`, mounted as guest `/var/lib`. The guest
  closure is a read-only store image, not a host store share.

## boundaries

- Egress defaults to closed, including DNS. Explicit `allowedTCPDestinations`
  are exceptions; open egress still seals other special-use ranges. IPv6 is
  dropped on the bridge. The seal's nftables chains run at `filter - 1`, before
  the host firewall; preserve both the seal and host firewall integration.
- `allowedDomains` requires closed egress. The host answers guest DNS with its
  bridge address and authorizes TLS by SNI without decrypting it or using proxy
  environment variables. `*.example.com` does not include `example.com`.
- `credentials` intercepts TLS for the credential's domain only: the guest's
  `/etc/hosts` points the domain at the bridge, the egress proxy hands the
  connection by SNI to the VM's Caddy, `fencr-<vm>-credentials.service`, on a Unix
  socket; it holds a certificate per granted domain from the per-host
  authority `fencr-ca.service` keeps in `/var/lib/fencr/ca` and injects that
  credential's header. The guest fetches the authority
  beside its secrets and rebuilds the system trust store at boot in
  `/run/fencr`. Raw `secrets` instead enter guest `/run/agent-secrets`, fetched
  at boot over vsock port 5 from a socket unit that serves the VM unit's
  systemd credentials; they are readable by guest root. Never put real secret
  values in the Nix store.
- SSH combines `fencr.adminKeys` and per-VM `authorizedKeys`; no keys means no
  SSH listener and no output-chain pinhole for it. Guest root is the intended
  privilege level. `expose` opens a guest port to every host process; it does
  not authenticate.
- The secrets relay uses `requisite`, not `requires`, for the VM unit: a
  connection must not start a stopped VM. Keep relay identities separate from
  VM users.
- Hosts need KVM and systemd-networkd. KSM is disabled. The VM unit runs as
  the VM's user with `/dev/kvm` and `/dev/net/tun` as its only devices and
  `UMask=0007`, which is what lets group `kvm` open its vsock; a CPU template
  hides vmx and svm from the guest. Stopping presses the guest's vsock power
  button (port 4), which reboots, because Firecracker exits on CPU reset.

## development and verification

Flake outputs cover `x86_64-linux` and `aarch64-linux`. Commands below use
`x86_64-linux`; substitute the builder's system when needed.

```bash
nix develop
nix fmt
nix build .#checks.x86_64-linux.formatting --no-link
nix build .#checks.x86_64-linux.core --no-link
nix build .#checks.x86_64-linux.cli --no-link
nix build .#checks.x86_64-linux.nixos-module --no-link
nix build .#checks.x86_64-linux.nixos-boot --no-link -L
nix flake check
```

- `treefmt.nix` enables nixfmt, deadnix, statix, mdformat, and rustfmt. The dev
  shell provides the treefmt wrapper. There is no default package to build;
  the CLI is installed by the NixOS module when VMs are declared.
- `checks/core.nix` probes pure builders and generated configuration through
  evaluation assertions. Extend it for derivation, validation, and unit changes.
- `checks/cli.nix` exercises the compiled CLI with mocked system commands.
- `checks/nixos-module.nix` asserts host/guest module wiring; its flake check
  builds the resulting NixOS toplevel, not just evaluation.
- `checks/nixos-boot.nix` runs a Firecracker guest inside a NixOS test VM,
  requiring nested KVM; the test VM uses `-cpu host` because Firecracker needs
  `KVM_CAP_XCRS`. It checks SSH, raw secrets, persistent state, ingress, denied
  traffic, domain egress, credential injection, and a clean stop. Its timeout
  is 1800 seconds; `nix flake check` includes this integration test.
- `effects.nix` defines nixbot's scheduled flake-input updates.
