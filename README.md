# fencr

Pronounced **fencer** /ˈfɛnsər/ — “fence” + “er”.

fencr runs AI agents in [Firecracker](https://firecracker-microvm.github.io/)
microVMs, configured as part of your NixOS host through
[microvm.nix](https://github.com/microvm-nix/microvm.nix).
You provide the agent; fencr controls its network access, credentials,
storage and resource limits.

## Highlights

- **Isolated workloads.** Each VM runs under its own unprivileged host user,
  with configurable CPU, memory, disk and network limits.
- **Controlled egress.** Outbound network access is denied by default,
  including DNS. Grant specific domains, destinations or host ports—or
  public internet access without opening private networks.
- **Host-held API keys.** The host injects credentials into permitted API
  requests instead of giving keys to the agent. Provider presets accept
  bare API keys from secret files or host commands.
- **Optional MCP gateway.** Give each VM an explicit set of tools while
  keeping backend credentials on the host. Use independent host-side
  approvals, or explicitly opt into client-mediated chat prompts.
- **Persistent state and checkpoints.** The guest's files survive rebuilds.
  Take disk checkpoints automatically or on demand, and restore when needed.
- **SSH access and visibility.** Use your SSH key to enter a VM;
  `fencr status` shows network grants, credential requests and blocked traffic.
- **Declarative operation.** Configure ordinary NixOS modules and deploy
  with `nixos-rebuild`. VMs run independently of your login session.

## Get started

Add the flake input:

```nix
inputs.fencr.url = "github:fosskar/fencr";
```

Import it into your NixOS host configuration:

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

Replace the public key and add your agent's NixOS module to `services`.
The host needs KVM. After deploying with `nixos-rebuild`:

```console
ssh myagent
fencr status myagent
fencr checkpoint myagent before-refactor
fencr restore myagent before-refactor
```

See the [quickstart](docs/quickstart.md) for defaults and further configuration.

## Scope and security

fencr does not ship an agent, select the agent's model provider, clone
repositories or mount host working trees. Your workload modules configure
those application details.

Host root is trusted, and SSH access to a VM is root access inside it.
An agent can still exercise the API permissions and tools you grant it;
keeping a credential on the host does not make those actions harmless.
An exposed `inbound` port is reachable by every host process and needs its
own application authentication.

The MCP gateway defaults to host-side approval and denies protected calls
without an approval command. It does not include a human approval UI.
Optional client-mediated prompts can appear in the same chat, but trust the
client to ask a human—a compromised client can approve its own calls.

## Documentation

- [Quickstart](docs/quickstart.md) — create a VM, defaults and resource limits
- [Network access](docs/networking.md) — inbound ports, egress grants and their limits
- [Credentials and secrets](docs/credentials.md) — provider presets, files, commands and OpenCode Go/Zen
- [MCP gateway](docs/mcp-gateway.md) — backend setup, per-VM tools and independent approvals
- [Access and operation](docs/access.md) — SSH, status, checkpoints and restore

Implementation lives in `modules/`, with pure builders in `modules/core/`
and the CLI, Go egress proxy and optional Python MCP gateway in `pkgs/`.
Checks cover their configuration and behavior, including a Firecracker VM
integration test.

Design history and boundaries:
[scope](docs/decisions/sandbox-only-scope.md),
[identity](docs/decisions/system-scoped-identity.md),
[SSH](docs/decisions/ssh-access-model.md),
[domain egress](docs/decisions/domain-egress-proxy.md),
[credentials](docs/decisions/credentials.md),
[hypervisor](docs/decisions/hypervisor.md), and
[checkpoints](docs/decisions/checkpoints.md).
