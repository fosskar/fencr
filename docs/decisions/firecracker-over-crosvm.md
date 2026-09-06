# firecracker over crosvm

Accepted 2026-09-06: the port passed `checks.nixos-boot` with the check's
assertions unchanged, under nested kvm. The three prerequisites below had
landed first. What the port found on the way is under "what the port
changes"; what it costs is at the end.

## what changed since crosvm-over-qemu.md

crosvm was chosen for its jailed file device: guest root became an
unprivileged host uid through a uid map, and the state tree could stay a
host directory. That reason goes away when the state tree becomes a block
image owned by the vm's user. The other reasons weigh less than the record
assumed:

- per-device jails contain a device bug to one device's process. In a
  one-process vmm under a jailer and seccomp, the same bug lands in a
  process that holds only its own vm's disk, tap and vsock, which the guest
  already controls. The next step is a kernel bug either way. firecracker
  also has fewer devices to have bugs in: no virtio-fs, no fw_cfg, no acpi
  tables, no gpu.
- the hybrid vsock model is a porting cost, not a boundary. A guest-to-host
  connection arrives on a unix socket whose path belongs to one vm; in the
  vm's own runtime directory, owned by the vm's user, the path is the
  identity. Host-to-guest needs a `CONNECT <port>` handshake, which the
  relay can do.
- fw_cfg was only needed for raw `secrets`. They now ride the vsock: at
  boot the guest fetches one tar stream from a host socket only its user
  can open, served from the unit's systemd credentials. No firmware
  device, nothing in the store, nothing on disk.

## facts

Sources: firecracker `README.md`, `CREDITS.md`, `docs/design.md`,
`docs/vsock.md`, `docs/prod-host-setup.md`; microvm.nix
`lib/runners/firecracker.nix` at the pinned revision.

- one process per microvm, started by a `jailer` that sets up cgroup,
  chroot and namespaces, then drops privileges; "thread-specific seccomp
  filters"; a "minimalist design" that "excludes unnecessary devices"
- devices: block, net, vsock, balloon, entropy, pmem. No virtio-fs
- vsock: the host side is an `AF_UNIX` socket; host-initiated connections
  send `CONNECT <port>\n` and get `OK <port>\n`; guest-initiated
  connections to port N reach `<uds_path>_N` on the host. The host does not
  learn a peer cid; it does not need to
- the codebase "started with code from" crosvm; `CREDITS.md` names the
  crosvm authors
- versioned releases; production at AWS Lambda and Fargate; the hypervisor
  under E2B, Fly and Vercel sandboxes
- the microvm.nix runner supports tap by name, block volumes and vsock, and
  throws on virtio-fs shares and on `credentialFiles`. After the
  prerequisites below neither is used, so the runner needs no patch

## prerequisites, hypervisor-independent, all landed first

1. block image for the state tree. Removed virtio-fs, the uid range,
   `CAP_SETUID`/`CAP_SETGID` on the vm unit, the bind mount and the setup
   unit, on crosvm as well
1. credentials declared once and granted by name, and raw `secrets`
   removed with them
1. transparent SNI proxy for `allowedDomains`. Not required for the port;
   it replaced tinyproxy and the guest proxy environment in the same
   sequence

## what the port changes

- firecracker's vsock on the host is a unix socket, `/run/fencr-<vm>/vsock`,
  created by firecracker as the vm's user; the vm unit's umask lets group
  kvm, the relays, open it. The runner's own path for it lives in the
  working directory and is wiped on every start, so fencr names its own
- guest-to-host forwards are socket units on `/run/fencr-<vm>/vsock_<port>`,
  owned by the vm's user with mode 0600: the path is the identity, only that
  vm's firecracker can open it. The relay's cid check and its unsafe
  `getpeername` went away
- host-to-guest relays and the ssh door speak firecracker's `CONNECT <port>`
  handshake through `fencr-vsock-forward connect`. The ssh door is a socket
  every host account may open, `/run/fencr-ssh-<vm>`, so the access model
  (`ssh-access-model.md`) holds unchanged
- the guest must not see the host's virtualization flags. crosvm had
  `--nested mode=off`; firecracker takes a cpu template that clears two
  cpuid bits, generated from the bit numbers
- firecracker's only shutdown signal is an emulated keyboard's
  ctrl-alt-del, and the nixos kernel's `i8042` driver fails to probe that
  keyboard. fencr does not use it: the guest runs a power button on vsock
  port 4 that reboots on any connection, which is how a firecracker guest
  ends, since firecracker exits on cpu reset and a power-off only halts.
  The stop script presses it and waits for firecracker to exit. Only the
  vm's user and the relays can open the vsock. The boot check fails on a
  stop timeout
- firecracker leaves its vsock socket behind; the unit removes it before
  each start
- the microvm.nix patch, the fw_cfg ssdt, the user-namespace assertion, the
  vhost-vsock device and the `vhost_vsock` module go away

## cost

- no memory balloon: microvm.nix's firecracker runner refuses it, so a vm
  keeps its `MemoryMax` cap but does not return unused memory to the host
- the runner boots the unstripped `vmlinux` from the kernel's `dev` output;
  larger closure per guest than crosvm's bzImage
- the boot check's host needs `-cpu host`: firecracker requires
  `KVM_CAP_XCRS`, which the synthetic `kvm64` model does not offer a nested
  hypervisor. A real host offers it
- a policy crosvm expressed as one flag is thirty lines of cpu template

## why it is still the better trade

Fewer devices, one process, versioned releases, no patch to carry, and the
hypervisor the field settled on. Against `main` the port removed more lines
than it added.
