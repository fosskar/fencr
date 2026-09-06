# firecracker over crosvm (proposed)

Status: proposed 2026-09-06, tracked in the firecracker pull request. crosvm
stays until a port has passed `checks.nixos-boot` and run on a real host.
Three changes come first and do not depend on the hypervisor; the decision
is taken after them, on a test result.

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
- fw_cfg is only needed for raw `secrets`. systemd also reads
  `systemd.set_credential=` from the kernel command line, and firecracker's
  boot arguments live in its configuration, not in host argv.

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

## prerequisites, hypervisor-independent

1. block image for the state tree. Removes virtio-fs, the uid range,
   `CAP_SETUID`/`CAP_SETGID` on the vm unit, the bind mount and the setup
   unit, on crosvm as well
1. credential gateway (issue 6). Raw `secrets` become the escape hatch and
   the only user of a hypervisor credential transport
1. transparent SNI proxy for `allowedDomains`. Not required for the port;
   listed because it replaces tinyproxy and the guest proxy environment
   and so belongs in the same sequence

## what the port changes

- `fencr-vsock-forward` and `fencr proxy` learn the handshake; the
  `ssh <vm>` alias uses `fencr proxy`
- host forward sockets become `ListenStream=/run/fencr-<name>/v.sock_<port>`
  in the vm's runtime directory; the relay's cid check becomes the socket's
  owner and mode
- raw `secrets` ride `systemd.set_credential_binary=` on the kernel command
  line; the fw_cfg ssdt and the microvm.nix patch go away
- `--nested mode=off` has no equivalent; the boot check already asserts the
  guest sees neither `svm` nor `vmx` and decides this

## decide by

A branch where `checks.nixos-boot` passes under firecracker, unchanged in
what it asserts, plus:

- the check runs under nested kvm, as it does today
- balloon returns memory to the host; `MemoryMax` holds
- boot time and resident memory of the vm unit, beside crosvm's

If it passes, firecracker is the simpler system: fewer devices, versioned,
no patches, the hypervisor the field settled on. If it fails on something
structural, this record is closed with the reason and crosvm stays.

## cost of not switching

crosvm is a rolling main with no releases; fencr carries a two-line patch
to microvm.nix's runner and an ssdt for fw_cfg, and turns KSM off because
crosvm marks all guest memory mergeable.
