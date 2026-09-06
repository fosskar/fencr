# crosvm over qemu

Superseded the same day by `firecracker-over-crosvm.md`; kept for the
reasoning that still holds, the rejection of qemu and cloud-hypervisor.

Accepted 2026-09-06 after a run on a real host (nixbox, one agent vm with
three services and a migrated state tree).

fencr runs its microvms on crosvm. It started on qemu; cloud-hypervisor was
rejected early because its vsock is the hybrid unix-socket model, where
host-to-guest connections need a handshake helper and guest-to-host
connections arrive on per-port unix sockets without a peer cid to check.
crosvm on Linux uses the kernel's vhost-vsock, so host socket units bind
vsock ports, the relays see the guest's cid, and ssh over vsock works
unchanged.

## why

- every virtio device runs in its own minijail with seccomp, on by default;
  qemu is one process behind one seccomp filter
- the file server for the state tree is a jailed device in a user namespace,
  not a root daemon: guest root is an unprivileged host uid by construction
- nested virtualization is a flag (`--nested mode=off`), not a cpu feature
  string
- a tap is attached by name without any capability

## decisions

- crosvm replaces qemu; there is no hypervisor option. every forward path
  would exist twice and the seal semantics could drift between two runners
- raw `secrets` keep their shape: crosvm's fw_cfg device carries the systemd
  credentials, and the guest gets an ssdt declaring qemu's QEMU0002 node
  because crosvm exposes no acpi node and the nixos kernel's driver takes no
  command line parameter; both boot checks read a staged secret
- the state tree is a disk image, `/var/lib/fencr-vms/<name>/state.img`,
  owned by the vm's user and created by the runner on first start. it
  replaced a virtio-fs share with a per-vm uid range: no file server faces
  the guest, the unit holds no capability, and the host cannot browse the
  vm's files without mounting the image while the vm is stopped. a state
  tree from before the change is copied into the image by hand
- the shared credential gateway (issue 6) is separate work; it does not remove
  the need for raw secrets

## what the hypervisor unit gives up

Two knobs of the shared hardening set are off for crosvm, because the tests
failed with them on: `ProcSubset` and `ProtectProc`, since the device jails
remount /proc in their namespaces. `AF_INET` is allowed for the tap ioctls;
crosvm opens no network socket.

The unit runs as a system user of its own, `fencr-<name>` in group `kvm`, so
two vms' crosvm processes share no host identity and the state image has an
owner that outlives the unit, which `DynamicUser` would not give it.

## cost

- crosvm is a rolling main with no releases; nixpkgs ships a dated snapshot
- crosvm marks all guest memory mergeable, so KSM stays off on the host
- unprivileged user namespaces must be allowed on the host
- microvm.nix's crosvm runner refuses `credentialFiles`; fencr passes them
  through `crosvm.extraArgs`
- microvm.nix's crosvm runner attaches the store image with the deprecated
  `-r`, which makes crosvm add `root=/dev/vda` to the kernel command line and
  the systemd initrd fails on two root mounts; it also boots the unstripped
  `vmlinux`, 380 MiB per guest, where crosvm takes the bzImage. fencr applies
  a two-line patch to the runner at evaluation time
  (`modules/microvm-crosvm-block.patch`, import from derivation); it goes
  away once upstream takes both
