# hypervisor

fencr runs its microvms on Firecracker through microvm.nix, since
2026-09-06. This file is the history of that choice: every hypervisor
considered, why it was taken or left, and what each move added or removed.
Nothing here is a rule. A later port starts from what these two ports
learned, not from their conclusions.

## timeline

- start: qemu through microvm.nix
- 2026-09-06: crosvm replaced qemu, accepted after a run on a real host
  (nixbox, one agent vm with three services and a migrated state tree)
- 2026-09-06, the same day: Firecracker replaced crosvm, accepted after
  `checks.nixos-boot` passed with its assertions unchanged, under nested kvm

## qemu, the start

- one process behind one seccomp filter; no per-device isolation
- nested virtualization was hidden through a cpu feature string
- raw `secrets` rode fw_cfg: microvm.nix's `credentialFiles`, read by the
  guest through the QEMU0002 acpi node

Nothing was removed on the way to crosvm; qemu was the baseline the crosvm
record measured against.

## cloud-hypervisor, rejected without a run

Rejected early because its vsock is the hybrid unix-socket model:
host-to-guest connections need a `CONNECT` handshake and guest-to-host
connections arrive on per-port unix sockets without a peer cid to check.
At the time the relays checked the guest's cid, so that was disqualifying.

The same vsock model is what Firecracker has, and fencr accepted it later
that day once the socket path became the identity. The reason no longer
holds. cloud-hypervisor was not re-evaluated after that; it is a candidate
with no findings, not a rejected one.

## crosvm, used for one day

Taken for:

- every virtio device in its own minijail with seccomp, on by default
- the file server for the state tree was a jailed device in a user
  namespace, not a root daemon: guest root was an unprivileged host uid by
  construction
- nested virtualization off is a flag, `--nested mode=off`
- a tap attached by name without any capability

What it required:

- raw `secrets` through crosvm's fw_cfg device, plus an ssdt declaring
  qemu's QEMU0002 node, because crosvm exposes no acpi node and the nixos
  kernel's driver takes no command line parameter
- microvm.nix's crosvm runner refused `credentialFiles`; fencr passed them
  through `crosvm.extraArgs`
- a two-line patch to the runner, `modules/microvm-crosvm-block.patch`,
  applied by import from derivation: the runner attached the store image
  with the deprecated `-r`, which added `root=/dev/vda` and made the systemd
  initrd fail on two root mounts, and it booted the unstripped `vmlinux`
  where crosvm takes a bzImage
- `ProcSubset` and `ProtectProc` off on the vm unit, because the device
  jails remount /proc in their namespaces; `AF_INET` allowed for the tap
  ioctls
- unprivileged user namespaces on the host
- a rolling main with no releases; nixpkgs ships a dated snapshot
- crosvm marks all guest memory mergeable. KSM is off on a fencr host for a
  reason of its own, same-page merging lets a guest probe memory across
  vms, so this cost nothing extra

Decided while on crosvm, and still standing:

- the state tree is a disk image, `/var/lib/fencr-vms/<name>/state.img`,
  owned by the vm's user and created by the runner on first start. It
  replaced the virtio-fs share and its per-vm uid range: no file server
  faces the guest, the unit holds no `CAP_SETUID`/`CAP_SETGID`, and the host
  cannot browse the vm's files without mounting the image while the vm is
  stopped. A state tree from before the change is copied into the image by
  hand
- the vm unit runs as a system user of its own, `fencr-<name>` in group
  `kvm`, so two vms' hypervisor processes share no host identity and the
  state image has an owner that outlives the unit, which `DynamicUser`
  would not give it
- there is no hypervisor option. Every forward path would exist twice and
  the seal semantics could drift between two runners

Why it was left: the block image took away crosvm's reason. The jailed file
device had made guest root an unprivileged host uid; with no file server
the vm's user owns the image and that is the whole boundary. Per-device
jails weigh less than the crosvm record assumed: in a one-process vmm the
same device bug lands in a process that holds only its own vm's disk, tap
and vsock, which the guest already controls, and the next step is a kernel
bug either way. What remained was a rolling snapshot and a patch to carry.

## Firecracker, current

Facts, from firecracker's `README.md`, `CREDITS.md`, `docs/design.md`,
`docs/vsock.md`, `docs/prod-host-setup.md` and microvm.nix's
`lib/runners/firecracker.nix` at the pinned revision:

- one process per microvm, started by a `jailer` that sets up cgroup,
  chroot and namespaces, then drops privileges; "thread-specific seccomp
  filters"; a "minimalist design" that "excludes unnecessary devices"
- devices: block, net, vsock, balloon, entropy, pmem. No virtio-fs, no
  fw_cfg, no acpi tables, no gpu
- vsock: the host side is an `AF_UNIX` socket; host-initiated connections
  send `CONNECT <port>\n` and get `OK <port>\n`; guest-initiated
  connections to port N reach `<uds_path>_N` on the host. The host does not
  learn a peer cid; it does not need to
- the codebase "started with code from" crosvm; `CREDITS.md` names the
  crosvm authors
- versioned releases; production at AWS Lambda and Fargate; the hypervisor
  under E2B, Fly and Vercel sandboxes
- the microvm.nix runner supports tap by name, block volumes and vsock, and
  throws on virtio-fs shares and on `credentialFiles`. Neither is used, so
  the runner needs no patch

Three hypervisor-independent changes landed on crosvm first and made the
port small: the block image for the state tree, credentials declared once
and granted by name, and the transparent SNI proxy for `allowedDomains`.
Raw `secrets` were considered for removal and kept, for keys a program must
hold itself (`credentials.md`).

What the port changed:

- Firecracker's vsock on the host is a unix socket, `/run/fencr-<vm>/vsock`,
  created by Firecracker as the vm's user; the vm unit's umask lets group
  `kvm`, the relays, open it. The runner's own path for it lives in the
  working directory and is wiped on every start, so fencr names its own
- guest-to-host forwards are socket units on `/run/fencr-<vm>/vsock_<port>`,
  owned by the vm's user with mode 0600: the path is the identity, only that
  vm's Firecracker can open it. The relay's cid check and its unsafe
  `getpeername` went away
- host-to-guest relays and the ssh door speak the `CONNECT <port>`
  handshake through `fencr-vsock-forward connect`. The ssh door is a socket
  every host account may open, `/run/fencr-ssh-<vm>`, so the access model
  (`ssh-access-model.md`) holds unchanged
- raw `secrets` ride the vsock: at boot the guest fetches one tar stream
  from a host socket only its user can open, served from the unit's systemd
  credentials. No firmware device, nothing in the store, nothing on disk,
  and no longer x86-only
- the guest must not see the host's virtualization flags. crosvm had one
  flag; Firecracker takes a cpu template that clears two cpuid bits,
  generated from the bit numbers
- Firecracker's only shutdown signal is an emulated keyboard's ctrl-alt-del,
  and the nixos kernel's `i8042` driver fails to probe that keyboard. fencr
  does not use it: the guest runs a power button on vsock port 4 that
  reboots on any connection, which is how a Firecracker guest ends, since
  Firecracker exits on cpu reset and a power-off only halts. The stop script
  presses it and waits for Firecracker to exit; the boot check fails on a
  stop timeout
- Firecracker leaves its vsock socket behind; the unit removes it before
  each start
- the runner boots `vmlinux` from the kernel's `dev` output, 400 MiB with
  debug symbols; fencr strips it to 57 MiB. A bzImage needs Firecracker
  1.17, unreleased (issue 10)

Removed with crosvm: the microvm.nix patch, the fw_cfg ssdt, the
user-namespace assertion, the vhost-vsock device and the `vhost_vsock`
module, the cid check in the relay.

Carried over without a new test: `ProcSubset` and `ProtectProc` are still
off on the vm unit. They were turned off for crosvm's device jails; whether
Firecracker runs with them on has not been tried.

Cost:

- no memory balloon: microvm.nix's Firecracker runner refuses it, so a vm
  keeps its `MemoryMax` cap but does not return unused memory to the host
- the boot check's host needs `-cpu host`: Firecracker requires
  `KVM_CAP_XCRS`, which the synthetic `kvm64` model does not offer a nested
  hypervisor. A real host offers it
- a policy crosvm expressed as one flag is thirty lines of cpu template

Why it was the better trade: fewer devices, one process, versioned
releases, no patch to carry, and the hypervisor the field settled on.
Against `main` the port removed more lines than it added.
