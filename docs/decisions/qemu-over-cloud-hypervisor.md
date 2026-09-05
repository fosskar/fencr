# qemu over cloud-hypervisor

fencr runs its microvms on qemu with vhost-vsock, not cloud-hypervisor.

## context

The source tree originally used cloud-hypervisor. Its vsock is the "hybrid"
unix-socket-mediated model: host-to-guest connections need a helper that
dials the VM's control socket and speaks the handshake, and guest-initiated
AF_VSOCK connections toward the host land on per-port unix sockets rather
than a real vsock address space. That forced a custom rust connector for
every forward and made guest-to-host channels awkward.

## why qemu

- real AF_VSOCK both directions: the host binds `vsock::<port>` directly in
  systemd socket units, guests dial host CID 2, and `getpeername` returns a
  hypervisor-guaranteed peer CID usable as access control
- plain `socat VSOCK-CONNECT:<cid>:<port>` replaces the custom connector
- systemd's ssh-over-vsock (`ssh vsock%<cid>`) works, so guest access needs
  no bridge IP and no host key persisted on the state volume
- balloon with free-page reporting and deflate-on-oom works the same

## why not both, qemu default

Offering cloud-hypervisor as a second hypervisor option was considered and
rejected. Hybrid vsock is not a drop-in alternative transport: host-to-guest
forwards need a handshake connector instead of `VSOCK-CONNECT`, and
guest-to-host channels (hostForwards, the credential broker) arrive on
per-port unix sockets instead of a vsock address space with peer CIDs. Every
forward path would exist twice, and the seal semantics could drift between
the two implementations — the same failure mode the flakelet decision guards
against with the shared core. cloud-hypervisor's lower per-VM memory
overhead is real; it can return as an option when someone brings that need
and a benchmark, priced against a second transport implementation.

## cost

- qemu's memory overhead per VM is higher than cloud-hypervisor's
- microvm.nix's qemu runner has no notify socket support, so the microvm
  unit is `Type=simple`: the host knows the process started, not that the
  guest booted
