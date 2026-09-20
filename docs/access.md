# accessing a sandbox

A sandbox has an ssh door only when keys authorize it: `fencr.adminKeys`
(every sandbox) or `fencr.sandboxes.<name>.authorizedKeys` (that sandbox). Without either,
`fencr ssh` refuses by name, rather than letting the bare name fall through
to dns and reach whatever else answers to it. The door is the
guest's sshd on the sandbox's address on its bridge, `fencr.sandboxes.<name>.ip`,
and the sandbox's firewall lets the host reach that port and the sandbox's `inbound` ports,
nothing else. You are root inside the sandbox; the sandbox boundary is the privilege
boundary. An `inbound` port has no SSH key check: every host process can
connect to it. See [network access](networking.md) for that distinction.

## on the host the sandbox runs on

```console
ssh <sandbox-name>
```

The module writes a `Host <sandbox-name>` alias into the system ssh
configuration with the sandbox's address as `HostName`. Authentication is your
own ssh key against the sandbox's authorized list, not your host privileges.

## from another machine (sandbox runs on a server)

The sandbox's address is private to the server, so the connection jumps
through it. Name the server and `fencr ssh` does the rest:

```console
FENCR_HOST=server fencr ssh <sandbox-name>
```

The jump lands on `fencr-jump-<sandbox-name>`, a host account the module
creates for every sandbox that has keys. Its authorized entries read:

```
restrict,port-forwarding,permitopen="10.11.0.2:22" ssh-ed25519 AAAA... you
```

`restrict` removes the pty, the shell and every kind of forwarding;
`port-forwarding` gives back the one kind a jump is, and `permitopen`
leaves it one destination. So the account opens a channel to
that one sandbox's sshd and can do nothing else on the server — not a shell,
not another sandbox, not the lan. The sandbox's own sshd still authenticates you,
against the same keys as always.

That is what lets you hand someone a sandbox without an account on the
server in any useful sense. A key in `fencr.sandboxes.<name>.authorizedKeys`
reaches that sandbox; a key in `fencr.adminKeys` is in every sandbox's list and so
reaches all of them.

Without the command installed, the same thing by hand — `fencr list` on
the server prints the address:

```
Host myvm
  HostName 10.11.0.2
  User root
  ProxyJump fencr-jump-myvm@server
```

Either way your ssh authenticates directly against the sandbox, and the
server only forwards bytes: it never sees your agent, and no key of
yours has to be usable on it.

On the host itself the same tool covers the day-to-day reads:

```console
fencr list                    # declared sandboxes: id, ip, inbound and outbound grants
fencr ssh sbx                 # shell in the sandbox
fencr status sbx              # grants and their use, blocked traffic, credential requests
fencr status --watch          # the same, refreshed
fencr checkpoint sbx [name]   # copy the sandbox's disk now
fencr checkpoints sbx         # list the copies; --rm <name> removes one
fencr restore sbx <name>      # stop, put the copy in place, start
```

`list` and `status` read; `ssh` runs as guest root; `checkpoint` and
`restore` change the sandbox's state, not its configuration. Changing a sandbox's
configuration means changing the system configuration and running
`nixos-rebuild`.

For the optional [MCP gateway](mcp-gateway.md), `fencr status` shows HTTP
requests to `mcp.fencr`, not individual tool calls or approval decisions.
Gateway diagnostics are in `journalctl -u fencr-mcp-gateway.service`.

## host root, stated plainly

For host root, ssh is a convenience, not the boundary: it owns the sandbox's
state image, console and the hypervisor process.
`adminKeys` gives that fact an auditable ssh-shaped form. For every
other host account, the key check is the real gate.

## the state image is never mounted on the host

`/var/lib/fencr-sandboxes/<name>/state.img` is a filesystem guest root wrote.
Mounting it on the host (`mount -o loop`) hands that filesystem to the
host kernel's ext4 parser, which is the one attack a compromised guest
gets at the host's kernel from its disk. Inspect a stopped sandbox's disk in
userspace instead, or boot it in a throwaway sandbox:

```console
# debugfs -R 'ls -l /root' /var/lib/fencr-sandboxes/<name>/state.img
# debugfs -R 'cat /root/notes.md' /var/lib/fencr-sandboxes/<name>/state.img
```

The same holds for every file under `checkpoints/`.

## checkpoints

A checkpoint is a copy of the state image beside it, taken by
`fencr checkpoint <sandbox> [name]` while the sandbox runs, after every clean stop
(`checkpoints.onStop`, on by default, named `stop-<utc stamp>`) and on
an optional timer (`checkpoints.interval`, named `timer-<utc stamp>`).
`fencr checkpoints <sandbox>` lists them, `fencr restore <sandbox> <name>` stops
the sandbox, puts the copy in the image's place and starts it again; the
stop leaves a checkpoint of what was replaced. Automatic kinds keep the
last `checkpoints.keep`; named ones stay until
`fencr checkpoints <sandbox> --rm <name>`.

The copy is a reflink, instant and sharing blocks with the image until
either side writes; btrfs, xfs and OpenZFS 2.3 with `block_cloning`
have them. Without reflinks only stop checkpoints are taken, as plain
sparse copies.

Checkpoints contain disk state, not memory. A running checkpoint does not
pause the sandbox or flush application buffers; treat it like recovery after a
crash, not an application-consistent backup. Restore reboots the guest into
the saved disk state. Host-side credentials and MCP gateway state are not
part of a guest checkpoint.

## reusing root's authorized keys as adminKeys

Deliberately not automatic. Root's authorized list may contain
restricted entries (`restrict,command="..."` automation keys); fencr
re-authorizes bare keys and would silently discard those restrictions,
promoting a single-purpose key to unrestricted sandbox root. If your root
list is clean, opting in is one explicit line:

```nix
fencr.adminKeys = config.users.users.root.openssh.authorizedKeys.keys;
```
