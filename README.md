# fencr

Pronounced **fencer** /ˈfɛnsər/ — “fence” + “er”.

fencr is a NixOS module for running AI agents in microVMs with explicit
network permissions, persistent storage and resource limits. It uses
[Firecracker](https://firecracker-microvm.github.io/) through
[microvm.nix](https://github.com/microvm-nix/microvm.nix).

VMs run as system-wide systemd services, independent of login sessions.
Their configuration belongs to the NixOS host; changes are deployed with
`nixos-rebuild`. SSH public keys authorize access to each VM, rather than
assigning a VM to a host account.

fencr does not include an agent, configure model providers, clone
repositories or mount host working trees. `fencr.vms.<name>.services`
accepts ordinary NixOS modules that install and configure the workload.
Those modules are also responsible for getting code into the VM.

## Highlights

- API keys never enter the VM: the host terminates the API's TLS and injects
  the header; a compromised agent can spend a key but not read it, and
  `allow` entries bound what it can spend it on.
- Deny by default, including DNS. Grants are single strings: a server name,
  a host port, an address and port, or `"internet"` without private ranges;
  `"!name"` carves a name out of a wildcard grant.
- One Firecracker microVM per agent, run by its own unprivileged user in an
  empty root, with CPU, memory, disk, network and connection caps.
- Plain NixOS configuration, deployed with `nixos-rebuild`; no daemon, no
  database.
- The guest persists like a machine; only its Nix store is replaced. A
  checkpoint of its disk is taken after every clean stop, on demand, or on a
  timer, and `fencr restore` puts one back.
- `fencr status` shows what each grant carried, every request a credential
  rode on, and what was blocked, with the entry that would allow it.

## Configuration

Add the flake input:

```nix
inputs.fencr.url = "github:fosskar/fencr";
```

Import the module into your NixOS host configuration, with `fencr` available
as the flake input:

```nix
{ fencr, pkgs, ... }:
{
  imports = [ fencr.nixosModules.fencr ];

  networking.useNetworkd = true;

  fencr.vms.myagent = {
    authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
    services = [
      { environment.systemPackages = [ pkgs.ripgrep ]; }
    ];
  };
}
```

Replace the example public key with your own and add your agent's NixOS
module to `services`. Each VM gets an `id` from its position in name
order, which derives its subnet `10.11.<id>.0/26`, mac and vsock cid;
adding a VM whose name sorts earlier moves the ones after it, so set `id`
to pin one.

The host requires `/dev/kvm` and systemd-networkd. The module enables
nftables and disables kernel same-page merging (KSM). A swap partition
without `randomEncryption` draws a warning at evaluation: guest memory is
the hypervisor's memory and would land on it in plain text.

By default, each VM has:

- no network egress, including external DNS;
- SSH at the VM's address on its bridge, enabled only when authorized keys
  are configured;
- 4 vCPUs, 4096 MiB of guest memory, a systemd `MemoryMax` 512 MiB above
  it and `400%` `CPUQuota`; disk and network bandwidth unlimited; at most
  2048 open connections;
- a 32768 MiB sparse disk image as its root filesystem, stored on the host
  at `/var/lib/fencr-vms/<name>/state.img`, whose flushes reach the host
  disk (Firecracker's `Writeback` cache), with a copy taken after every
  clean stop and the last five kept;
- a read-only image containing its Nix store closure, without a host store
  share.

`vcpu`, `mem`, `memoryMax`, `cpuQuota`, `stateSize`, `diskBandwidth`,
`networkBandwidth` and `maxConnections` configure these limits;
`checkpoints.onStop`, `checkpoints.interval` and `checkpoints.keep` the
copies. Increasing `stateSize` grows the state image on the next start; it
does not shrink existing images.

## Network access

Network permissions are configured in two lists per VM:

```nix
fencr.vms.myagent = {
  inbound = [ 8080 ];
  outbound = [
    "github.com"
    "*.github.com"
    "host:8123"
    "192.168.20.0/24:1234"
  ];
};
```

`inbound` lists guest TCP ports the host may reach at
`fencr.vms.<name>.ip`. The guest service must listen on that address, not
loopback. These ports are not published to the LAN or internet.

Each `outbound` string grants one kind of access:

| Entry | Effect |
| --- | --- |
| `"github.com"` | TLS on port 443 to that server name. No port suffix. |
| `"*.github.com"` | TLS on port 443 to subdomains, not bare `github.com`. |
| `"!gist.github.com"` | Refuses a name a wildcard grant would otherwise admit. |
| `"host:8123"` | TCP to port 8123 on the host, over the VM's bridge. |
| `"192.168.20.0/24:1234"` | TCP to an IPv4 address or subnet and port, including private destinations. |
| `"internet"` | Public IPv4 internet access and DNS. Private and other special-use ranges remain blocked unless explicitly granted. |

`"internet"` may accompany host/address grants, but not domain grants.
Both lists default to empty: no explicit access, including DNS. SSH keys
and credential grants automatically enable their required access, shown
alongside explicit grants in `fencr status`. Reply traffic needs no separate
grant.

Domain grants check TLS Server Name Indication (SNI), not HTTP paths or
methods. It does not support plain HTTP or connections without a visible
server name. Shared CDN infrastructure can allow a client to reach a
different site through an allowed server name; this is not application-level
request filtering. See [domain egress](docs/decisions/domain-egress-proxy.md).

`inbound` does not authenticate clients: any process on the host can connect
to an exposed port. Services on those ports must provide their own
authentication.

## Credentials and secrets

A granted credential lets a VM call an HTTPS API with the secret header
added on the host:

```nix
fencr.credentials.anthropic.secretFile = "/run/secrets/anthropic";

fencr.vms.myagent.credentials = [ "anthropic" ];
```

A credential named `anthropic`, `openai`, `openrouter` or `opencode` takes
its `upstream` and `header` from that provider; `provider = "openrouter"`
does the same under another name, and `upstream` and `header` remain
settable for any other API:

```nix
fencr.credentials.mine = {
  upstream = "https://api.example.com";
  header = "x-api-key";
  secretFile = "/run/secrets/example";
};
```

The workload calls `https://api.anthropic.com` as it would anywhere. Inside
the VM the name resolves to the host, where the VM's egress unit ends the
TLS with a certificate from a per-host certificate authority the VM trusts,
replaces the header with the secret value and sends the request on. A
client that insists on a key can be given any placeholder. The VM's system
trust store carries the authority; Python's `certifi` and Node read it
through `NIX_SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`, which fencr sets. A
client that pins the upstream's real certificate cannot use a credential.

The agent can exercise every API permission the credential grants unless
`allow` narrows it to methods and paths; a request outside the list is
answered 403 on the host and never reaches the upstream. Every request a
credential rides on is logged with its method, path and status, which
`fencr status` lists:

```nix
fencr.credentials.github = {
  upstream = "https://api.github.com";
  secretFile = "/run/secrets/github";
  allow = [
    "GET,HEAD *"
    "POST /repos/*/pulls"
  ];
};
```

This works for any HTTPS API that takes its secret in a header, so `gh`,
`npm` or an MCP server behind `domain = "mcp.fencr"` use it like a model
provider does.

An upstream on host loopback has no name a VM could call; give it one with
`domain`, for example `domain = "mcp.fencr"` for
`upstream = "http://127.0.0.1:8764"`.

When a workload needs the raw value instead, use
`fencr.vms.myagent.secrets."agent.env" = "/run/secrets/agent.env";`.
The file appears at `/run/agent-secrets/agent.env` inside the VM and is
readable by guest root. The guest fetches raw `secrets` over vsock at boot
from a host socket only that VM's user can open. See
[credentials](docs/decisions/credentials.md) for the transport and trust
model.

## Access and operation

The module installs the `fencr` command on the host:

```console
fencr list
fencr status myagent
fencr status --watch
fencr checkpoint myagent before-refactor
fencr checkpoints myagent
fencr restore myagent before-refactor
ssh myagent
```

A checkpoint is a copy of the VM's disk beside it, instant where the host
filesystem has reflinks (btrfs, xfs, OpenZFS 2.3); `restore` stops the VM,
puts the copy in place and starts it again. See
[access](docs/access.md#checkpoints).

`fencr.vms.<name>.authorizedKeys` authorizes root SSH access to one VM;
`fencr.adminKeys` authorizes root SSH access to every VM. Host root remains
trusted: it controls the hypervisor, state images and secrets regardless of
these key lists.

For end-to-end SSH from another machine, jump through the host to the VM's
address (`fencr list` prints it):

```sshconfig
Host myagent
  HostName 10.11.0.2
  User root
  ProxyJump server
```

Replace `server` with your host's SSH alias. This requires SSH access to the
host as well as a key authorized in the VM; it does not require agent
forwarding. See [access](docs/access.md) for other connection methods.

## Implementation and design

The NixOS module lives in `modules/`, the pure builders it composes
in `modules/core/`, and the `fencr` command and the egress program in `pkgs/`. Flake
checks cover the NixOS module, the builders, the CLI, the egress program and
NixOS boot integration. Firecracker replaced crosvm, which had replaced
QEMU; [the hypervisor record](docs/decisions/hypervisor.md) holds the
history, the costs, and what Firecracker's production host guidance
changed: the hypervisor process runs in an empty read-only root as its
jailer would build, guest flushes reach the host disk, and the guest has
a virtio-rng.

The design decisions explain the scope and security model:

- [Sandbox only, no agent](docs/decisions/sandbox-only-scope.md)
- [System-scoped identity](docs/decisions/system-scoped-identity.md)
- [SSH access model](docs/decisions/ssh-access-model.md)
- [Domain egress](docs/decisions/domain-egress-proxy.md)
- [Credentials](docs/decisions/credentials.md)
- [Hypervisor](docs/decisions/hypervisor.md)
- [Checkpoints](docs/decisions/checkpoints.md)
