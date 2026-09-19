# accessing a vm

A vm has an ssh door only when keys authorize it: `fencr.adminKeys`
(every vm) or `fencr.vms.<name>.authorizedKeys` (that vm). Without either,
`fencr ssh` refuses by name, rather than letting the bare name fall through
to dns and reach whatever else answers to it. The door is the
guest's sshd on the vm's address on its bridge, `fencr.vms.<name>.ip`,
and the vm's firewall lets the host reach that port and the vm's `inbound` ports,
nothing else. You are root inside the vm; the vm boundary is the privilege
boundary. An `inbound` port has no SSH key check: every host process can
connect to it. See [network access](networking.md) for that distinction.

## on the host the vm runs on

```console
ssh <vm-name>
```

The module writes a `Host <vm-name>` alias into the system ssh
configuration with the vm's address as `HostName`. Authentication is your
own ssh key against the vm's authorized list, not your host privileges.

## from another machine (vm runs on a server)

The vm's address is private to the server, so the connection jumps
through it. Name the server and `fencr ssh` does the rest:

```console
FENCR_HOST=server fencr ssh <vm-name>
```

The jump lands on `fencr-jump-<vm-name>`, a host account the module
creates for every vm that has keys. Its authorized entries read:

```
restrict,permitopen="10.11.0.2:22" ssh-ed25519 AAAA... you
```

`restrict` removes the pty, the shell and every kind of forwarding;
`permitopen` leaves one destination. So the account opens a channel to
that one vm's sshd and can do nothing else on the server — not a shell,
not another vm, not the lan. The vm's own sshd still authenticates you,
against the same keys as always.

That is what lets you hand someone a sandbox without an account on the
server in any useful sense. A key in `fencr.vms.<name>.authorizedKeys`
reaches that vm; a key in `fencr.adminKeys` is in every vm's list and so
reaches all of them.

Without the command installed, the same thing by hand — `fencr list` on
the server prints the address:

```
Host myvm
  HostName 10.11.0.2
  User root
  ProxyJump fencr-jump-myvm@server
```

Either way your ssh authenticates directly against the vm, and the
server only forwards bytes: it never sees your agent, and no key of
yours has to be usable on it.

On the host itself the same tool covers the day-to-day reads:

```console
fencr list                    # declared vms: id, ip, inbound and outbound grants
fencr ssh sbx                 # shell in the vm
fencr status sbx              # grants and their use, blocked traffic, credential requests
fencr status --watch          # the same, refreshed
fencr checkpoint sbx [name]   # copy the vm's disk now
fencr checkpoints sbx         # list the copies; --rm <name> removes one
fencr restore sbx <name>      # stop, put the copy in place, start
```

`list` and `status` read; `ssh` runs as guest root; `checkpoint` and
`restore` change the vm's state, not its configuration. Changing a vm's
configuration means changing the system configuration and running
`nixos-rebuild`.

For the optional [MCP gateway](mcp-gateway.md), `fencr status` shows HTTP
requests to `mcp.fencr`, not individual tool calls or approval decisions.
Gateway diagnostics are in `journalctl -u fencr-mcp-gateway.service`.

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

Checkpoints contain disk state, not memory. A running checkpoint does not
pause the VM or flush application buffers; treat it like recovery after a
crash, not an application-consistent backup. Restore reboots the guest into
the saved disk state. Host-side credentials and MCP gateway state are not
part of a guest checkpoint.

## reusing root's authorized keys as adminKeys

Deliberately not automatic. Root's authorized list may contain
restricted entries (`restrict,command="..."` automation keys); fencr
re-authorizes bare keys and would silently discard those restrictions,
promoting a single-purpose key to unrestricted vm root. If your root
list is clean, opting in is one explicit line:

```nix
fencr.adminKeys = config.users.users.root.openssh.authorizedKeys.keys;
```
