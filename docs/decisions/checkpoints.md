# checkpoints

A vm's whole state is one image, `/var/lib/fencr-vms/<name>/state.img`,
and until 2026-09-10 nothing kept a copy of it: an agent that broke its
own machine had no way back short of the host's backups. Fly Sprites
sells exactly this ("statefulness, with an undo button"), E2B pauses and
snapshots, Docker Sandboxes has nothing. This is the record of what fencr
took and what it left.

## what a checkpoint is

A copy of the state image beside it, `checkpoints/<name>.img`, owned by
the vm's user like the image. Three ways one comes to exist:

- after every clean stop, from the vm unit's `ExecStopPost`, named
  `stop-<utc stamp>`. A `nixos-rebuild` that restarts the vm, or a
  restore, leaves the state it replaced behind. `checkpoints.onStop`, on
  by default
- on demand, `fencr checkpoint <vm> [name]`, while the vm runs
- on a calendar, `checkpoints.interval`, named `timer-<utc stamp>`, off by
  default

The automatic kinds keep the last `checkpoints.keep` (five) each; named
ones stay until `fencr checkpoints <vm> --rm <name>`. `fencr restore`
stops the vm, puts the copy in the image's place and starts it: the vm
reboots into the checkpointed disk.

## disk only

No memory. A restore is a reboot, and a payload comes back from its disk
after every rebuild anyway, so a memory image would add a file the size
of guest ram per checkpoint, a restore bound to the identical Firecracker
and cpu, vsock connections reset on resume, and Firecracker's own warning
that resuming one state twice is insecure, since randomness and tokens
repeat. Fly restores by restart as well. E2B keeps memory because its
sandboxes are ephemeral and must resume in milliseconds; fencr's are
permanent and reboot in seconds.

## the copy is a reflink

`cp --reflink=always`: the copy shares blocks with the image until either
side writes, so it is instant and takes no space at first. The clone is
one atomic operation on the file, so a running vm's copy is a point-in-time
image of what reached the host disk, which the state drive's `Writeback`
cache keeps complete: crash-consistent, as the stop path is. btrfs, xfs
(`reflink=1`, the default since 2019) and OpenZFS 2.3 with
`feature@block_cloning` have reflinks; ext4 does not.

Where there are none, a running copy would take minutes of racing the
guest, so it is refused with the reason; stop checkpoints fall back to a
plain sparse copy, since nothing waits on the stop path. On btrfs the
runner marks the image nodatacow, and btrfs clones only between files
with matching attributes, so the copy is given the image's before the
clone.

E2B and Fly avoid the filesystem question by owning the block layer: a
userspace copy-on-write block device (E2B's nbd server, Fly's storage)
under Firecracker. For a file-backed image the host filesystem's reflink
is the only zero-cost copy there is. The filesystem-independent route for
fencr would be device-mapper thin volumes instead of files, a storage
model change with its own record if it is ever wanted. Firecracker's
vhost-user block backend, the other hook, is a developer preview.

## not paused

The running copy does not pause the vm. Pausing through the api
(`PATCH /vm {"state":"Paused"}`) was implemented and reverted the same
day: Firecracker 1.16 leaves host-to-guest vsock delivery dead after a
bare pause/resume, fixed in 1.17 (`#6100`), and the power button on vsock
port 4 rides on it, so every stop after a checkpoint ran into the 60 s
timeout and left no stop checkpoint. The pause would only have shrunk
the window of guest writes not yet flushed; the clone's atomicity gives
the consistency. Issue 23 brings it back with 1.17.

## the image is never mounted on the host

A checkpoint invites inspection, and the obvious `mount -o loop` hands a
filesystem guest root wrote to the host kernel's ext4 parser. E2B goes out
of its way to never do that, reading images with `debugfs` in a jailed
process. `docs/access.md` states the rule and the `debugfs` way for the
image and every copy.

## in the unit, not the command

The copy runs in `fencr-<vm>-checkpoint@<name>.service` as the vm's user
in the vm unit's own empty root, with the api socket as its only reach;
the command starts the unit and relays its error. Restore runs in the
command as root, since it must stop and start the vm, and copies with
`--preserve=ownership` so the image keeps its owner. `fencr checkpoint`
and `fencr restore` are the first `fencr` commands that change a vm's
state; they do not change its configuration, which stays with
`nixos-rebuild`.
