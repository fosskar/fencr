# fencr

Give an AI agent a real NixOS machine of its own, and keep the parts that
matter outside it. fencr runs agents in persistent
[Firecracker](https://firecracker-microvm.github.io/) microVMs where the
network, the API keys and the tools they may use are decided on the host.

An agent needs a shell, a network and an API key to be useful. Give it those
on your own machine and it has your SSH keys, your repositories, your LAN and
a key it can spend. Give it a VM and it has a machine — but the key is still
inside it, and it can still reach anything. fencr draws the line one level
out: the key never enters the VM, every connection out is judged by the host,
and every MCP tool call can require your approval first.

Built on [microvm.nix](https://github.com/microvm-nix/microvm.nix), with full
NixOS configuration inside each VM.

*Pronounced **fencer** /ˈfɛnsər/ — “fence” + “er”.*

## What it looks like

```console
$ fencr status myagent
myagent  RUNNING  10.11.0.2  memory 412M
VMM: Running
Inbound (from host):
  ✓ TCP 22, 9119 (22: ssh)                    3 packets
Outbound (otherwise denied):
  ✓ github.com TLS 443                        1 connection
  ✓ *.github.com TLS 443                      2 connections
  ✓ !gist.github.com TLS 443 (denied)         1 connection
  ✓ api.anthropic.com TLS 443 (credential anthropic)  6 connections

Blocked (journal, rate-limited sample):
  ✗ guest → evil.test:443/tls         x1     outbound "evil.test"
  ✗ guest → gist.github.com:443/tls   x1     denied by outbound "!gist.github.com"

Credential requests (journal):
  POST api.anthropic.com/v1/messages → 200  x6

Services: egress RUNNING
```

Every grant shows as used or unused, every block says which rule stopped it,
and the credential log lists methods, paths and status codes — never headers.

## Highlights

- **API keys the VM never holds.** The guest gets a placeholder; the host
  injects the real key into permitted HTTP methods and paths only, and scrubs
  it back out of the response so an API that echoes a request cannot leak it.
  Each VM has its own certificate authority. Presets for Anthropic, OpenAI,
  OpenRouter and OpenCode Go/Zen; secret files, Clan vars and host commands
  supported.
- **MCP tool permissions and approval.** Put existing MCP servers behind one
  gateway that enforces per-agent tool grants and asks before execution — allow
  calendar lookups, for example, but require approval to create events. Backend
  tokens stay on the host.
- **Egress the host decides.** VMs get public IPv4 and DNS; the LAN and other
  special-use ranges stay shut. Narrow that to an allowlist of domains, IP/port
  pairs or host ports, or to nothing at all with `outbound = [ ]`. A granted
  domain is matched by the TLS server name and spliced through without being
  decrypted; only a credential's own domain is terminated.
- **Persistent disks and rollback.** Keep work across rebuilds. Checkpoint on
  clean stops, on a schedule or on demand; restore disk state when needed.
- **A real machine, fenced in.** Separate kernels, disks and unprivileged host
  users, no host working-tree mounts, and per-VM limits on CPU, memory, disk
  size, disk and network bandwidth, and connection counts.

## What fencr is not

- It ships **no agent**. You supply one as a NixOS module through
  `fencr.vms.<name>.services`; fencr provides the machine and the boundary.
- It does **not clone repositories** or mount your working tree into the VM.
- It is **not a container runtime** or a multi-tenant platform. One host, VMs
  you declare, `nixos-rebuild` as the control plane.

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

## Documentation

- [How fencr works](docs/overview.md) — the units, the road out and what is refused where
- [Quickstart](docs/quickstart.md) — create a VM, defaults and resource limits
- [Network access](docs/networking.md) — inbound ports, egress grants and their limits
- [Credentials and secrets](docs/credentials.md) — provider presets, files, commands and OpenCode Go/Zen
- [MCP gateway](docs/mcp-gateway.md) — tool permissions, host approvals and in-chat prompts
- [Access and operation](docs/access.md) — SSH, status, checkpoints and restore

Design rationale: [decision records](docs/decisions/).

## Security boundaries

Host root is trusted; SSH grants guest root. Host-held keys do not prevent
abuse or disclosure through allowed APIs. See [credential restrictions](docs/credentials.md).

The optional MCP gateway requires a host approval command by default;
no approval UI is bundled. In-chat approval is an opt-in that trusts the
client—a compromised client can approve its own calls.

## Status and license

Early. The interfaces described here work and are covered by the checks in
`checks/`, including a booting guest under nested KVM, but options may still
change between releases. Issues and questions are welcome.

MIT. See [LICENSE](LICENSE).
