# fencr

Pronounced **fencer** /ˈfɛnsər/ — “fence” + “er”.

Persistent [Firecracker](https://firecracker-microvm.github.io/) microVMs
built for AI agents on NixOS. Network, API and tool permissions enforced
on the host.
Built on [microvm.nix](https://github.com/microvm-nix/microvm.nix), with full
NixOS configuration inside each VM.

## Highlights

- **VM isolation.** Separate kernels, disks and unprivileged host users.
  No host working-tree mounts.
- **Deny-by-default networking.** Grant domains, IP/port pairs or host ports.
  Public internet access can be enabled without opening private networks.
- **Host-held API keys.** Inject credentials only into permitted HTTP methods
  and paths. Presets for Anthropic, OpenAI, OpenRouter and OpenCode Go/Zen;
  secret files, Clan vars and host commands supported.
- **MCP gateway.** Enforce per-agent tool permissions and approval before
  execution across existing MCP servers. Allow calendar lookups, for example,
  but require approval to create events. Backend tokens stay on the host.
- **Persistent disks and rollback.** Keep work across rebuilds. Checkpoint
  on clean stops, on a schedule or on demand; restore disk state when needed.
- **Per-VM resource limits.** CPU, memory, disk size, disk/network bandwidth
  and connection counts.
- **SSH and visibility.** `fencr status` reports network permissions,
  blocked traffic and proxied API requests.

## Get started

You need a NixOS host with KVM. Add fencr to your flake inputs:

```nix
inputs.fencr.url = "github:fosskar/fencr";
```

Import the module and declare a VM:

```nix
{ fencr, pkgs, ... }:
{
  imports = [ fencr.nixosModules.fencr ];
  networking.useNetworkd = true;

  fencr.vms.myagent = {
    authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
    outbound = [ "github.com" ];
    services = [
      { environment.systemPackages = [ pkgs.ripgrep ]; }
    ];
  };
}
```

Replace the key, add your agent's module to `services` and deploy with
`nixos-rebuild`.

```console
ssh myagent
fencr status myagent
fencr checkpoint myagent before-refactor
```

`fencr restore myagent before-refactor` replaces the current guest disk
with the checkpoint and restarts the VM.

## Security boundaries

Host root is trusted; SSH grants guest root. Host-held keys do not prevent
abuse or disclosure through allowed APIs. See [credential restrictions](docs/credentials.md).

The optional MCP gateway requires a host approval command by default;
no approval UI is bundled. In-chat approval is an opt-in that trusts the
client—a compromised client can approve its own calls.

## Documentation

- [Quickstart](docs/quickstart.md) — create a VM, defaults and resource limits
- [Network access](docs/networking.md) — inbound ports, egress grants and their limits
- [Credentials and secrets](docs/credentials.md) — provider presets, files, commands and OpenCode Go/Zen
- [MCP gateway](docs/mcp-gateway.md) — tool permissions, host approvals and in-chat prompts
- [Access and operation](docs/access.md) — SSH, status, checkpoints and restore

Design rationale: [decision records](docs/decisions/).
