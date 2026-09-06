# ssh access: admin keys plus owner keys

Two tiers, both plain ssh public keys:

- `fencr.adminKeys` — every listed public key is authorized as root in every vm.
- `fencr.vms.<name>.authorizedKeys` — authorized as root in that vm only.
  The owner tier: a vm belongs to whoever holds these keys.

The guest authorizes the union. The vsock sshd (socket-activated, vsock
port 22) exists only when the union is non-empty — no keys, no door. The
host writes an `ssh <vm-name>` alias whose `ProxyCommand` crosses vsock;
vsock connect is unprivileged, so any host user holding an authorized key
logs in with their own identity.

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
hypervisor process, the state image, the staged secrets and the
serial console. adminKeys does not grant host root anything new; it only
gives that fact an ssh-shaped, auditable form.

## earlier shape, removed

`fencr.admin.{identityFile,publicKey}` (one global keypair, forced
`IdentityFile` on the alias) was an extraction artifact of the source
tree's clan wiring, not a design. Replaced by the two key lists; the
alias now leaves authentication to the caller's own ssh configuration.
