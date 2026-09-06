# crosvm over qemu (proposed)

Status: proposed, tracked in the crosvm pull request. `qemu` stays until the
port has run on a real host.

fencr moves its microvms from qemu to crosvm. The reason that kept qemu over
cloud-hypervisor does not apply: crosvm on Linux uses the kernel's vhost-vsock,
so host socket units bind vsock ports, the relays see the guest's cid, and ssh
over vsock works unchanged.

## why

- every virtio device runs in its own minijail with seccomp, on by default;
  qemu is one process behind one seccomp filter
- the file server for the state tree is a jailed device in a user namespace,
  not a root daemon: guest root is an unprivileged host uid by construction
- nested virtualization is a flag (`--nested off`), not a cpu feature string
- a tap is attached by name without any capability

## decisions

- crosvm replaces qemu; there is no hypervisor option. two runner paths for
  secrets and shares would drift, the same argument as for cloud-hypervisor
- raw `secrets` keep their shape: crosvm's fw_cfg device carries the systemd
  credentials, and the guest kernel gets `qemu_fw_cfg.ioport=` because crosvm
  exposes no acpi node for the device. proven by a check before anything else
- the state tree maps guest uids to a per-vm range of host uids; crosvm holds
  CAP_SETUID and CAP_SETGID for that mapping and nothing else. guest root
  becomes an unprivileged host uid, non-root guest users keep working, and one
  vm cannot reach another vm's files. existing state trees are chowned once
- the shared credential gateway (issue 6) is separate work; it does not remove
  the need for raw secrets

## cost

- crosvm is a rolling main with no releases; nixpkgs ships a dated snapshot
- crosvm marks all guest memory mergeable, so KSM stays off on the host
- unprivileged user namespaces must be allowed on the host
- microvm.nix's crosvm runner refuses `credentialFiles` and uses an external
  virtiofsd instead of crosvm's own file device; fencr bypasses it for both
