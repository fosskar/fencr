# fencr

Sealed microVM sandboxes for AI agents, as NixOS options.

You say what the agent may reach. fencr does the firewall.

```nix
fencr.vms.myagent = {
  id = 0;
  services = [ my-agent-module ];

  # internet: yes. LAN, mesh, sibling VMs: no. that is the default.
  # egress = "closed" blocks everything beyond the pinholes, dns included.
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
- egress: internet allowed, every private range dropped — a compromised
  agent cannot walk your LAN, your mesh, or a sibling sandbox
- explicit pinholes for the private destinations you name
- host↔guest port forwards over vsock, socket-activated, no TCP exposure
- persistent `/var/lib` per instance; read-only nix store share
- memory ceiling with balloon, hard cap on the unit, CPU quota

## Status

Extraction in progress from a private nixfiles repository, where this runs
in production for a homelab agent fleet. The module lands here after the
vsock transport rework settles there.

## Non-goals

fencr ships no agent. Bring your own NixOS modules — hermes-agent, a shell
with claude code, anything. fencr is only the enclosure.
