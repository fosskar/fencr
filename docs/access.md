# accessing a vm

A vm has an ssh door only when keys authorize it: `fencr.adminKeys`
(every vm) or `fencr.vms.<name>.authorizedKeys` (that vm). The door is the
guest's sshd on the vm's address on its bridge, `fencr.vms.<name>.ip`,
and the vm's firewall lets the host reach that port and the vm's `inbound` ports,
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
  HostName 10.11.0.2
  User root
  ProxyJump server
```

Your ssh authenticates directly against the vm; the server only forwards
the connection and never sees your agent.

Quick, interactive, without a config entry: double-ssh through the
server's own alias:

```console
ssh -t server fencr list
ssh -t server ssh <vm-name>
```

Authentication happens *on the server*, so your key must be usable
there (`-A` agent forwarding works; be aware server root can use the
forwarded agent while connected).

On the host itself the same tool covers the day-to-day reads:

```console
fencr list        # declared vms: id, ip, inbound and outbound grants
fencr ssh sbx     # shell in the vm
fencr status sbx  # the vm unit plus its proxy and credential units
```

Every command but `ssh` is a read; changing a vm's configuration means
changing the system configuration and running `nixos-rebuild`.

## host root, stated plainly

For host root, ssh is a convenience, not the boundary: it owns the vm's
state image, console and the hypervisor process.
`adminKeys` gives that fact an auditable ssh-shaped form. For every
other host account, the key check is the real gate.

## the state image is never mounted on the host

`/var/lib/fencr-vms/<name>/state.img` is a filesystem guest root wrote.
Mounting it on the host (`mount -o loop`) hands that filesystem to the
host kernel's ext4 parser, which is the one attack a compromised guest
gets at the host's kernel from its disk. Inspect a stopped vm's disk in
userspace instead, or boot it in a throwaway vm:

```console
# debugfs -R 'ls -l /root' /var/lib/fencr-vms/<name>/state.img
# debugfs -R 'cat /root/notes.md' /var/lib/fencr-vms/<name>/state.img
```

The same holds for every file under `checkpoints/`.

## checkpoints

A checkpoint is a copy of the state image beside it, taken by
`fencr checkpoint <vm> [name]` while the vm runs, after every clean stop
(`checkpoints.onStop`, on by default, named `stop-<utc stamp>`) and on
an optional timer (`checkpoints.interval`, named `timer-<utc stamp>`).
`fencr checkpoints <vm>` lists them, `fencr restore <vm> <name>` stops
the vm, puts the copy in the image's place and starts it again; the
stop leaves a checkpoint of what was replaced. Automatic kinds keep the
last `checkpoints.keep`; named ones stay until
`fencr checkpoints <vm> --rm <name>`.

The copy is a reflink, instant and sharing blocks with the image until
either side writes; btrfs, xfs and OpenZFS 2.3 with `block_cloning`
have them. Without reflinks only stop checkpoints are taken, as plain
sparse copies.

## reusing root's authorized keys as adminKeys

Deliberately not automatic. Root's authorized list may contain
restricted entries (`restrict,command="..."` automation keys); fencr
re-authorizes bare keys and would silently discard those restrictions,
promoting a single-purpose key to unrestricted vm root. If your root
list is clean, opting in is one explicit line:

```nix
fencr.adminKeys = config.users.users.root.openssh.authorizedKeys.keys;
```
