# accessing a vm

A vm has an ssh door only when keys authorize it: `fencr.adminKeys`
(every vm) or `fencr.vms.<name>.authorizedKeys` (that vm). The door is a
socket-activated sshd on vsock — no IP, no network listener. You are
root inside the vm; the vm boundary is the privilege boundary.

## on the host the vm runs on

```console
ssh <vm-name>
```

The module writes a `Host <vm-name>` alias into the system ssh
configuration whose `ProxyCommand` crosses vsock. vsock connect is
unprivileged, so this works from any host account — authentication is
your own ssh key against the vm's authorized list, not your host
privileges.

## from another machine (vm runs on a server)

A vm has no TCP address, so `ProxyJump` does not apply. Two ways:

Quick, interactive:

```console
ssh -t server ssh <vm-name>
```

Uses the server's alias. Authentication happens *on the server*, so your
key must be usable there (`-A` agent forwarding works; be aware server
root can use the forwarded agent while connected).

Clean, end-to-end — put this in your own `~/.ssh/config`:

```
Host myvm
  User root
  ProxyCommand ssh server fencr proxy <vm-name>
```

The `fencr` command ships with the module on every fencr host; `proxy`
resolves the vm name to its vsock address server-side. Your ssh
authenticates directly against the vm; the server only shuttles bytes
and never sees your agent.

On the host itself the same tool covers the day-to-day reads:

```console
fencr list        # declared vms: id, cid, ip, egress, domain count
fencr ssh sbx     # shell in the vm
fencr status sbx  # the vm unit plus its forward/proxy/broker units
```

`fencr update` exists only to tell you where updates actually happen:
the system configuration on a nixos host, `flakelet update` on a
flakelet host. fencr deliberately has no mutating commands —
`nixos-rebuild` is the control plane.

## host root, stated plainly

For host root, ssh is a convenience, not the boundary: it owns the vm's
state directory, staged secrets, console and the hypervisor process.
`adminKeys` gives that fact an auditable ssh-shaped form. For every
other host account, the key check is the real gate.

## reusing root's authorized keys as adminKeys

Deliberately not automatic. Root's authorized list may contain
restricted entries (`restrict,command="..."` automation keys); fencr
re-authorizes bare keys and would silently discard those restrictions,
promoting a single-purpose key to unrestricted vm root. If your root
list is clean, opting in is one explicit line:

```nix
fencr.adminKeys = config.users.users.root.openssh.authorizedKeys.keys;
```
