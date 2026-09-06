# crosvm over qemu

Accepted 2026-09-06 after a run on a real host (nixbox, one agent vm with
three services and a migrated state tree).

fencr moves its microvms from qemu to crosvm. The reason that kept qemu over
cloud-hypervisor does not apply: crosvm on Linux uses the kernel's vhost-vsock,
so host socket units bind vsock ports, the relays see the guest's cid, and ssh
over vsock works unchanged.

## why

- every virtio device runs in its own minijail with seccomp, on by default;
  qemu is one process behind one seccomp filter
- the file server for the state tree is a jailed device in a user namespace,
  not a root daemon: guest root is an unprivileged host uid by construction
- nested virtualization is a flag (`--nested mode=off`), not a cpu feature
  string
- a tap is attached by name without any capability

## decisions

- crosvm replaces qemu; there is no hypervisor option. two runner paths for
  secrets and shares would drift, the same argument as for cloud-hypervisor
- raw `secrets` keep their shape: crosvm's fw_cfg device carries the systemd
  credentials, and the guest gets an ssdt declaring qemu's QEMU0002 node
  because crosvm exposes no acpi node and the nixos kernel's driver takes no
  command line parameter; both boot checks read a staged secret
- the state tree maps guest uids to a per-vm range of 65536 host uids from
  1000000; crosvm holds CAP_SETUID and CAP_SETGID for that mapping and
  nothing else. guest root becomes an unprivileged host uid, non-root guest
  users keep working, and one vm cannot reach another vm's files. a state
  tree from before the port must be chowned into the range by hand
- the shared credential gateway (issue 6) is separate work; it does not remove
  the need for raw secrets

## what the hypervisor unit gives up

Four knobs of the shared hardening set are off for crosvm, each because the
tests failed with it on: `ProcSubset` and `ProtectProc` (the device jails
remount /proc in their namespaces), `RestrictSUIDSGID` and `UMask` (the file
device applies the guest's modes; a setuid bit on a file owned by an
unprivileged uid is harmless on the host). `AF_INET` is allowed for the tap
ioctls; crosvm opens no network socket.

## cost

- crosvm is a rolling main with no releases; nixpkgs ships a dated snapshot
- crosvm marks all guest memory mergeable, so KSM stays off on the host
- unprivileged user namespaces must be allowed on the host
- microvm.nix's crosvm runner refuses `credentialFiles` and uses an external
  virtiofsd instead of crosvm's own file device; fencr passes both through
  `crosvm.extraArgs`
- microvm.nix's crosvm runner attaches the store image with the deprecated
  `-r`, which makes crosvm add `root=/dev/vda` to the kernel command line and
  the systemd initrd fails on two root mounts; it also boots the unstripped
  `vmlinux`, 380 MiB per guest, where crosvm takes the bzImage. fencr applies
  a two-line patch to the runner at evaluation time
  (`modules/microvm-crosvm-block.patch`, import from derivation); it goes
  away once upstream takes both
