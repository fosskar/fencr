# ssh access: admin keys plus owner keys

Two tiers, both plain ssh public keys:

- `fencr.adminKeys` — every listed public key is authorized as root in every vm.
- `fencr.vms.<name>.authorizedKeys` — authorized as root in that vm only.
  The owner tier: a vm belongs to whoever holds these keys.

The guest authorizes the union. Its sshd, socket-activated on the vm's
address on its bridge, exists only when the union is non-empty — no keys,
no door, and no pinhole for it in the seal's output chain. The host writes
an `ssh <vm-name>` alias with that address as `HostName`, so any host user
holding an authorized key logs in with their own identity.

## the door was a vsock socket, until 2026-09-06

From crosvm until the evening of the Firecracker port the sshd listened on
vsock port 22 and the host offered a socket every host account could open,
`/run/fencr-ssh-<vm-name>`, with a relay per connection carrying the bytes
in. Exposed ports and guest-to-host forwards had the same shape: a socket
unit, a per-connection relay and a Rust program on the host, a listener in
the guest. The rule behind it, "no network listener anywhere", came from
the crosvm days when the bridge carried only the guest's internet traffic.

Firecracker put egress and then the credential interception on the bridge
anyway, so the vsock relays duplicated a road that already existed. What
the Firecracker field does, from their own docs: vsock carries the host's
control channel to an agent (Firecracker's `docs/vsock.md`,
firecracker-containerd's agent, Kata's ttRPC over vsock), and everything a
user connects to goes over the TAP network (Kata's pod ip, E2B's `envd` at
the sandbox's tap address, Fly's ssh server over WireGuard, Ignite's
`ssh`). fencr has no agent; its vsock relays carried what everyone else
carries over the network. They were removed: ssh and `expose` moved onto
the bridge, `hostForwards` went (`hostPorts` already reaches the host's
bridge address), and vsock kept the boot-time secrets fetch and the power
button, which are the control channel. The seal's output chain took over
the one thing the socket file had provided: only the guest's sshd and its
exposed ports are reachable from the host, and only while keys or `expose`
say so.

## why keys are the user model

fencr instances are workloads, not host accounts. A "user" renting a
sandbox for their coding agent need not exist as a linux user anywhere —
their public key is their identity, which also keeps the model identical
for humans, CI, and other machines. This deliberately diverges from
spaces-os, whose one-vm-per-host-user model fits a desktop and not a
server.

## why root inside the vm

The vm boundary is the privilege boundary; that is the product. An
unprivileged guest account would add ceremony inside a machine whose
entire filesystem, network and lifecycle already belong to its owner.

## stated plainly

Host root always reaches every vm regardless of any of this: it owns the
hypervisor process, the state image and the serial console. adminKeys does not grant host root anything new; it only
gives that fact an ssh-shaped, auditable form.

## earlier shape, removed

`fencr.admin.{identityFile,publicKey}` (one global keypair, forced
`IdentityFile` on the alias) was an extraction artifact of the source
tree's clan wiring, not a design. Replaced by the two key lists; the
alias now leaves authentication to the caller's own ssh configuration.
