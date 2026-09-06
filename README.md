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
    id = 0;
    authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
    services = [
      { environment.systemPackages = [ pkgs.ripgrep ]; }
    ];
  };
}
```

Replace the example public key with your own and add your agent's NixOS
module to `services`. Each VM needs a unique `id` between `0` and `8`.

The host requires `/dev/kvm` and systemd-networkd. The module enables
nftables and disables kernel same-page
merging (KSM). It uses the host's first `networking.nameservers` entry by
default; set `fencr.vms.<name>.dns` if the host has no resolver listed there.

By default, each VM has:

- no network egress, including external DNS;
- SSH at the VM's address on its bridge, enabled only when authorized keys
  are configured;
- 4 vCPUs, 4096 MiB of guest memory, a `4608M` systemd `MemoryMax` and
  `400%` `CPUQuota`;
- a 32768 MiB sparse disk image mounted at `/var/lib`, stored on the host at
  `/var/lib/fencr-vms/<name>/state.img`;
- a read-only image containing its Nix store closure, without a host store
  share.

`vcpu`, `mem`, `memoryMax`, `cpuQuota` and `stateSize` configure these limits.
Increasing `stateSize` grows the state image on the next start; it does not
shrink existing images.

## Network access

Network permissions are configured per VM:

| Option | Effect |
| --- | --- |
| `allowedTCPDestinations = [ "192.168.1.50:8123" ];` | Allow TCP to an IPv4 address or subnet and port, including an explicitly permitted private destination. |
| `allowedDomains = [ "github.com" "*.github.com" ];` | Allow TLS connections on port 443 by server name, without TLS interception or proxy environment variables. Requires `egress = "closed"`. |
| `egress = "open";` | Allow public IPv4 internet access and DNS. Private and other special-use ranges remain blocked unless explicitly permitted. |
| `expose = [ 8080 ];` | Let the host reach guest port 8080 at the VM's address, `fencr.vms.<name>.ip`. The service inside must listen on that address. Every other guest port is unreachable from the host. |
| `hostPorts = [ 8123 ];` | Allow access to a host TCP port over the VM's bridge. |

`allowedDomains` checks TLS Server Name Indication (SNI), not HTTP paths or
methods. It does not support plain HTTP or connections without a visible
server name. Shared CDN infrastructure can allow a client to reach a
different site through an allowed server name; this is not application-level
request filtering. See [domain egress](docs/decisions/domain-egress-proxy.md).

`expose` does not authenticate clients: any process on the host can connect
to an exposed port. Services on those ports must provide their own
authentication.

## Credentials and secrets

A granted credential lets a VM call an HTTPS API with the secret header
added on the host:

```nix
fencr.credentials.anthropic = {
  upstream = "https://api.anthropic.com";
  header = "x-api-key";
  secretFile = "/run/secrets/anthropic";
};

fencr.vms.myagent.credentials = [ "anthropic" ];
```

The workload calls `https://api.anthropic.com` as it would anywhere. Inside
the VM the name resolves to the host, where the credential's proxy ends the
TLS with a certificate from a per-host certificate authority the VM trusts,
replaces the header with the secret value and sends the request on. A
client that insists on a key can be given any placeholder. The VM's system
trust store carries the authority; Python's `certifi` and Node read it
through `NIX_SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`, which fencr sets. A
client that pins the upstream's real certificate cannot use a credential.
The agent can still exercise the API permissions the credential grants.
Method and path restrictions are not implemented.

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
fencr dashboard
ssh myagent
```

`fencr.vms.<name>.authorizedKeys` authorizes root SSH access to one VM;
`fencr.adminKeys` authorizes root SSH access to every VM. Host root remains
trusted: it controls the hypervisor, state images and secrets regardless of
these key lists.

For end-to-end SSH from another machine, jump through the host to the VM's
address (`fencr list` prints it):

```sshconfig
Host myagent
  HostName 10.30.1.2
  User root
  ProxyJump server
```

Replace `server` with your host's SSH alias. This requires SSH access to the
host as well as a key authorized in the VM; it does not require agent
forwarding. See [access](docs/access.md) for other connection methods.

## Implementation and design

The NixOS module, CLI, network and credential proxies are implemented in this
repository. Flake checks cover module evaluation, core configuration logic,
the CLI and NixOS boot integration. Firecracker replaced crosvm, which had
replaced QEMU; [the hypervisor record](docs/decisions/hypervisor.md) holds
the history and the costs.

The design decisions explain the scope and security model:

- [Sandbox only, no agent](docs/decisions/sandbox-only-scope.md)
- [System-scoped identity](docs/decisions/system-scoped-identity.md)
- [SSH access model](docs/decisions/ssh-access-model.md)
- [Hypervisor](docs/decisions/hypervisor.md)
