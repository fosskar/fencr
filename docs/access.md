# accessing a vm

A vm has an ssh door only when keys authorize it: `fencr.adminKeys`
(every vm) or `fencr.vms.<name>.authorizedKeys` (that vm). The door is the
guest's sshd on the vm's address on its bridge, `fencr.vms.<name>.ip`,
and the seal lets the host reach that port and the vm's `expose`d ports,
nothing else. You are root inside the vm; the vm boundary is the privilege
boundary.

## on the host the vm runs on

```console
ssh <vm-name>
```

The module writes a `Host <vm-name>` alias into the system ssh
configuration with the vm's address as `HostName`. Authentication is your
own ssh key against the vm's authorized list, not your host privileges.

## from another machine (vm runs on a server)

The vm's address is private to the server, so jump through it. Put this
in your own `~/.ssh/config`; `fencr list` on the server prints the
address:

```
Host myvm
  HostName 10.30.1.2
  User root
  ProxyJump server
```

Your ssh authenticates directly against the vm; the server only forwards
the connection and never sees your agent.

Quick, interactive, without a config entry (fencr installed on your
machine too):

```console
fencr -H server list
fencr -H server ssh <vm-name>
```

`-H` delegates the whole command to the server's fencr over ssh. Without
a local fencr, plain double-ssh works the same:

```console
ssh -t server ssh <vm-name>
```

Uses the server's alias. Authentication happens *on the server*, so your
key must be usable there (`-A` agent forwarding works; be aware server
root can use the forwarded agent while connected).

On the host itself the same tool covers the day-to-day reads:

```console
fencr list        # declared vms: id, cid, ip, egress, domain count
fencr ssh sbx     # shell in the vm
fencr status sbx  # the vm unit plus its proxy and credential units
```

Every command is a read; changing a vm means changing the system
configuration and running `nixos-rebuild`.

## host root, stated plainly

For host root, ssh is a convenience, not the boundary: it owns the vm's
state image, console and the hypervisor process.
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
