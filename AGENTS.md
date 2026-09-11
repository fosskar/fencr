# instructions

## scope

fencr provides sealed Firecracker microVMs through `nixosModules.fencr` (also
`nixosModules.default`). Payloads are NixOS modules supplied through
`fencr.vms.<name>.services`; fencr ships no agent, repository cloning, or host
working-tree mounts. `nixos-rebuild` is the control plane; the `fencr` CLI does
not mutate host configuration, but `fencr ssh` can run commands as guest root
and `fencr checkpoint`/`fencr restore` change a vm's disk state. Instance and
unit tables are compiled into its binary.

Design rationale lives in `docs/decisions/`. Consult the relevant record before
changing a boundary. `hypervisor.md` holds the qemu, crosvm and Firecracker
history and what each move cost, and what Firecracker's production host
guidance changed; `checkpoints.md` holds the copy model and why the vm is not
paused for one. `docs/quickstart.md` and `docs/access.md` describe
configuration, SSH access and the checkpoint commands.

## architecture

- `modules/options.nix` declares the options; `modules/default.nix`
  composes host networking, systemd units, users, and guest evaluations. Guests
  use the host's `pkgs`; payloads receive the resolved contract through
  `specialArgs.agentSandbox`.
- `modules/core/` holds the pure builders, one file per concern, joined by
  `default.nix` into one fixed point every part sees as `core`: `instance.nix`
  (`defaults`, derived names, `resolveInstance`, `hostErrors`),
  `hardening.nix` (unit hardening sets, `specialUseNetworks`), `vm.nix`
  (`vmService`), `firewall.nix` (the vm's nftables tables: `forwardRules`,
  `inputRules`, `outputRules`, `natRules`, `redirectRules`, `firewallOf`),
  `egress.nix` (the authority, `parseAllow`, and the vm's egress unit:
  `egressConfig`, `egressServiceConfig`, and the two bridge ports
  `egressDnsPort` and `egressTlsPort` that `redirectRules` reaches from the
  guest's 53 and 443),
  `checkpoint.nix` (`checkpointScript`, `checkpointUnits`, `apiSocketOf`),
  `host-units.nix` (`hostUnits`: services, sockets, timers) and `guest.nix`
  (`guestBase`, with the boot-time fetch in `guest-secrets.sh`). `emptyRootOf`
  in `hardening.nix` is the vm unit's and the checkpoint unit's sandbox. `guestPortsOf` in `instance.nix` is
  the one list of guest ports the host may reach; the guest firewall and the
  output chain both take it. Keep shared defaults in `core.defaults` and
  derivation logic here rather than duplicating it in the module or CLI.
  `resolveInstance` sorts `outbound` entries by kind into `internet`,
  `domains`, `denied`, `hostPorts` and `destinations`, one flat record with
  `inbound` and the derived names; `guestOf` selects the `guestFields` the
  guest receives as `agentSandbox`. Builders read those fields.
- `pkgs/cli/cli.rs` is the fencr command, `pkgs.writers.writeRustBin` with
  Rust edition 2024, not a Cargo workspace; `pkgs/cli/default.nix` appends its
  instance tables, tool paths and `pkgs/domain.rs` (`covers`, the one wildcard
  rule) at build. `checks/cli.nix` feeds the command a ruleset
  rendered by `firewallOf` and canned journal lines, so its parsers run on the
  text the firewall writes.
- `pkgs/egress/` is the vm's road out, one Go program, standard library only,
  so `buildGoModule` takes `vendorHash = null`: `dns.go` answers every A query
  with the bridge address, `sni.go` reads the server name from the client
  hello, `main.go` splices an allowed name onward or hands a credential's
  domain to `credentials.go`, which ends the TLS and injects the header. `nix build .#egress` builds it on its own and runs its tests.
- The bridge is the road between host and guest: the guest's sshd and its
  `inbound` ports listen on the guest's address, `fencr.vms.<name>.ip`, and the
  firewall's output chain lets the host reach those ports and nothing else. vsock
  carries only the boot-time secrets fetch and the power button: Firecracker's
  unix socket `/run/fencr-<name>/vsock`, in a directory only the VM's user
  enters, with guest-to-host port N arriving on `vsock_N` beside it and
  Firecracker's API socket at `api.sock`.
- Each VM runs as `fencr-<name>` with persistent state at
  `/var/lib/fencr-vms/<name>/state.img`, mounted as the guest's root
  filesystem: the whole guest persists across reboots and rebuilds, only
  `/nix/store` is replaced. The guest closure is a read-only store image, not
  a host store share. The state drive uses Firecracker's `Writeback` cache, so
  guest flushes reach the host disk; the runner's default would lose them.
  Copies of the image live in `checkpoints/` beside it, taken after every
  clean stop, by `fencr checkpoint` and by an optional timer, always with
  `cp --reflink=always` except on the stop path. Never mount a state image or
  a checkpoint on the host: `debugfs` reads them without the host kernel.

## boundaries

- `outbound` defaults to empty, including no DNS grant. Explicit IPv4/CIDR
  and port entries grant TCP access; `"internet"` grants public IPv4 and DNS
  but still blocks other special-use ranges. IPv6 is
  dropped on the bridge. The vm's nftables filter chains run at `filter - 1`, before
  the host firewall; preserve both the vm's tables and the host firewall integration.
- Domain grants in `outbound` cannot accompany `"internet"`. For domain
  grants, the host answers guest DNS with its
  bridge address and authorizes TLS by SNI without decrypting it or using proxy
  environment variables. `*.example.com` does not include `example.com`, and
  `"!name"` refuses a name a wildcard grant would otherwise admit; a deny no
  grant covers, or one equal to a grant, is an evaluation error.
- `credentials` intercepts TLS for the credential's domain only: the guest's
  `/etc/hosts` points the domain at the bridge, and the same unit that judges
  every other name ends this one itself, by SNI. It holds a certificate per
  granted domain from the per-host
  authority `fencr-ca.service` keeps in `/var/lib/fencr/ca` and injects that
  credential's header, read from `$CREDENTIALS_DIRECTORY` per request rather
  than from its environment, so a rotated `secretFile` needs no restart. `allow` entries scope a
  credential to methods and paths, and the host answers 403 itself for the
  rest; every request is logged without its headers, which `fencr status`
  lists. The guest fetches the authority
  beside its secrets and rebuilds the system trust store at boot in
  `/run/fencr`. Raw `secrets` instead enter guest `/run/agent-secrets`, fetched
  at boot over vsock port 5 from a socket-activated relay service that serves its
  own systemd credentials; they are readable by guest root. Never put real secret
  values in the Nix store.
- SSH combines `fencr.adminKeys` and per-VM `authorizedKeys`; no keys means no
  SSH listener and no output-chain pinhole for it. Guest root is the intended
  privilege level. `inbound` opens a guest port to every host process; it does
  not authenticate.
- The secrets relay uses `requisite`, not `requires`, for the VM unit: a
  connection must not start a stopped VM. Keep relay identities separate from
  VM users.
- Hosts need KVM and systemd-networkd, which brings systemd-resolved, the
  stub the egress units resolve through. KSM is disabled. The VM unit runs as
  the VM's user with `/dev/kvm` and `/dev/net/tun` as its only devices; group
  `kvm` is for those two. The unit's root is an empty read-only tmpfs with the store, the
  run directory and the state directory bound in, which is what Firecracker's
  jailer builds with its chroot. On x86_64, a CPU template hides vmx and svm from the guest. Stopping presses the guest's vsock power
  button (port 4), which reboots, because Firecracker exits on CPU reset.
- Beyond `cpuQuota` and `memoryMax`: `diskBandwidth` and `networkBandwidth`
  are Firecracker's token buckets on the state drive and the tap, unset by
  default; `maxConnections` is a `ct count` rule in the vm's forward and input
  chains, 2048 by default, counted per chain. A host with a swap partition and
  no `randomEncryption` draws a warning: guest memory is the hypervisor's
  memory.

## development and verification

Flake outputs cover `x86_64-linux` and `aarch64-linux`. Commands below use
`x86_64-linux`; substitute the builder's system when needed.

```bash
nix develop
nix fmt
nix build .#checks.x86_64-linux.formatting --no-link
nix build .#checks.x86_64-linux.core --no-link
nix build .#checks.x86_64-linux.cli --no-link
nix build .#checks.x86_64-linux.egress --no-link
nix build .#checks.x86_64-linux.nixos-module --no-link
nix build .#checks.x86_64-linux.nixos-boot --no-link -L
nix flake check
```

- `treefmt.nix` enables nixfmt, deadnix, statix, mdformat, rustfmt and gofmt. The dev
  shell provides the treefmt wrapper. There is no default package to build;
  the CLI is installed by the NixOS module when VMs are declared.
- `checks/core.nix` probes pure builders and generated configuration through
  evaluation assertions. Extend it for derivation, validation, and unit changes.
- `checks/cli.nix` exercises the compiled CLI with mocked system commands.
- `checks.egress` is the package itself: `buildGoModule` runs `pkgs/egress`'s
  own `go test` cases in its check phase.
- `checks/nixos-module.nix` asserts host/guest module wiring; its flake check
  builds the resulting NixOS toplevel, not just evaluation.
- `checks/nixos-boot.nix` runs a Firecracker guest inside a NixOS test VM,
  requiring nested KVM; on x86_64 the test VM uses `-cpu host` because Firecracker
  needs `KVM_CAP_XCRS`; on aarch64 it uses `-cpu cortex-a72`. The state
  images sit on a btrfs disk so reflinks exist. It checks SSH, raw secrets,
  persistent state, the hypervisor's empty root, ingress, denied traffic,
  domain egress with a deny entry, credential injection with `allow`
  entries and the access log, checkpoints and restore, and a clean stop.
  Its timeout is 1800 seconds; `nix flake check` includes this integration
  test.
- `effects.nix` defines nixbot's scheduled flake-input updates.
