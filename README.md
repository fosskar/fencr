# fencr

Sealed microVM sandboxes for AI agents, as NixOS options.

You say what the agent may reach. fencr does the firewall.

fencr is a system-wide service, not a user tool. It runs on the machine that
hosts the vms — server, VPS or workstation — independent of any login
session. Clients attach and prove who they are with an ssh key; a vm belongs
to whoever holds an authorized key, not to a system account. This is the
deliberate opposite of user-scoped sandboxes like Docker `sbx`
([docs/decisions/system-scoped-identity.md](docs/decisions/system-scoped-identity.md)).

```nix
fencr.vms.myagent = {
  id = 0;
  services = [ my-agent-module ];

  # egress is closed by default, including dns. grant only what is needed.
  allowedTCPDestinations = [ "192.168.1.50:8123" ];

  # or grant egress by name: implies a closed seal, everything routes
  # through a host-side proxy over vsock, allowlist enforced on the
  # CONNECT hostname — no tls interception
  # allowedDomains = [ "github.com" "*.github.com" ];

  # "expose" opens a host endpoint into the vm; 33627 is "fencr" on a
  # phone keypad and as good a default example as any
  expose = [ "33627" ];
  secrets."agent.env" = "/run/secrets/agent.env";
};
```

No daemon, no API server, no YAML. `nixos-rebuild` is the control plane —
or [flakelet](https://github.com/Mic92/flakelet), if the sandbox should
update independently of the host (`flakelets.default`).

## What you get

- one qemu microVM per instance ([microvm.nix](https://github.com/microvm-nix/microvm.nix)), vhost-vsock transport
- default-deny egress, including dns
- explicit pinholes for the destinations you name; optional open internet
  still blocks every private range
- host↔guest port forwards over vsock, socket-activated, no TCP exposure
- persistent `/var/lib` per instance; the guest's own closure on a read-only store image
- memory ceiling with balloon, hard cap on the unit, CPU quota

## Quickstart

[docs/quickstart.md](docs/quickstart.md) — the four-line config and what it gives you.

## Access

`fencr.adminKeys` grants every listed public key root access to every vm.
`fencr.vms.<name>.authorizedKeys` hands one vm to its owner — a public key
is the identity, no host account needed. `ssh <vm-name>` on the
host, `ProxyCommand ssh server fencr proxy <vm-name>` from anywhere
else. [docs/access.md](docs/access.md) has the detail.

## Status

Extraction in progress from a private nixfiles repository, where this runs
in production for a homelab agent fleet. The module lands here after the
vsock transport rework settles there.

## Non-goals

fencr ships no agent. Bring your own NixOS modules — hermes-agent, a shell
with claude code, anything. fencr is only the enclosure.

Getting code into a vm is payload too: fencr does not clone repositories or
mount host working trees. A `services` module fetches whatever it needs,
using a brokered credential if the source is private.
