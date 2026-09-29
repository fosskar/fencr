# quickstart

This sets up one sandbox on a NixOS machine, called the host below. Run
every command on the host unless a step says otherwise.

## what the host needs

- KVM, on `x86_64-linux` or `aarch64-linux`
- networkd: `networking.useNetworkd = true`, or at least
  `systemd.network.enable = true`. fencr checks for it but does not turn it on.
- systemd-resolved, which networkd turns on by default

## 1. configure the host

```nix
# flake input
inputs.fencr.url = "github:fosskar/fencr";

# host configuration
imports = [ fencr.nixosModules.fencr ];
networking.useNetworkd = true;

fencr.sandboxes.myagent = {
  services = [ my-agent-module ];
  authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
  outbound = [ ];
};
```

Replace `my-agent-module` with your agent's NixOS module and the key with your
own public key. fencr does not install or configure an agent.
`outbound = [ ]` blocks all network access, DNS included; leave it out and the
sandbox gets the public internet (see [grant access](#grant-access)).

## 2. deploy

Deploy the host the way you always do, for example with `nixos-rebuild`. This
builds and starts the sandbox and installs the `fencr` command on the host.

## 3. connect

On the host, as a user with a key from `authorizedKeys`:

```console
ssh myagent
```

fencr adds `myagent` to the host's SSH configuration, so the name resolves to
the sandbox. You are root inside it.

From another machine, such as your laptop, jump through the host. Add this to
`~/.ssh/config` there, with the address `fencr list` shows on the host:

```
Host myagent
  HostName 10.11.0.2
  User root
  ProxyJump fencr-jump-myagent@myhost
```

Then `ssh myagent` works from the laptop too. The jump account reaches this
one sandbox and nothing else on the host; see [access and operation](access.md).

## 4. look at it

On the host:

```console
fencr list                     # every sandbox with its address and grants
sudo fencr status myagent      # health, grants in use, blocked traffic
```

`fencr list` and `fencr ssh` work as any user. Everything else reads the
firewall, the journal or the sandbox's state and needs root.

What this sandbox has now:

- no network access, not even DNS. Credentials and MCP, once you add them,
  reach their own domains even with `outbound = [ ]`.
- one way in: SSH, with a key from `authorizedKeys`.
- a persistent disk. Everything survives reboots and rebuilds, except the
  read-only `/nix/store`, which each rebuild replaces.
- a disk checkpoint on every clean stop; the last five are kept.

## grant access

All of this goes in the host's configuration, followed by another
`nixos-rebuild switch`. Add only what the workload needs:

```nix
fencr.sandboxes.myagent = {
  outbound = [ "github.com" "*.github.com" "!gist.github.com" ];
  inbound = [ 9119 ];
};
```

Domains grant TLS on port 443. `"!name"` narrows a wildcard grant. You can
also grant an address and TCP port, `"192.168.1.50:8123"`, or a port on the
host, `"host:8080"`. Use `"internet"` instead of domain grants for public IPv4
access and DNS; private networks remain blocked unless explicitly granted.

`inbound` opens guest TCP ports to **every process on the host**, not only
your SSH key. The service must listen on the guest's address,
`fencr.sandboxes.myagent.ip`, and provide any required authentication. It is
not published to other machines. See [network access](networking.md).

For a provider credential:

```nix
fencr.credentials.opencode-go.secretFile = "/run/secrets/opencode-go";
fencr.sandboxes.myagent.credentials = [ "opencode-go" ];
```

`/run/secrets/opencode-go` is a file on the host containing just the API key.
The sandbox gets an `OPENCODE_GO_API_KEY` placeholder; the host inserts the
real header into requests to OpenCode. The agent still needs to select
OpenCode Go. See [credentials and secrets](credentials.md) for other
providers, Go and Zen together, host commands and raw guest secrets.

For MCP tools, see the [optional gateway](mcp-gateway.md). It automatically
wires per-sandbox credentials; each sandbox calls only the tools granted to it.

## workload and resource limits

`services` accepts ordinary NixOS modules:

```nix
fencr.sandboxes.myagent.services = [
  my-agent-module
  { environment.systemPackages = [ pkgs.ripgrep pkgs.nodejs ]; }
];
```

Default resources and the options that change them:

| Options | Default |
| --- | --- |
| `vcpu`, `mem` | 4 vCPUs, 4096 MiB guest memory |
| `cpuQuota`, `memoryMax` | `400%`, guest memory plus 512 MiB |
| `stateSize` | 32768 MiB sparse root disk |
| `diskBandwidth`, `networkBandwidth` | Unset; configure in MiB/s |
| `maxConnections` | 2048 per connection-counting firewall chain |
| `checkpoints.onStop`, `checkpoints.keep` | Enabled, five automatic checkpoints of each kind |
| `checkpoints.interval` | Unset; for example `"hourly"` |

These are per-sandbox options under `fencr.sandboxes.<name>`. Increasing `stateSize`
grows the disk at the next start; decreasing it does not shrink existing
images. Checkpoints while running require a reflink-capable host filesystem;
stop checkpoints can fall back to ordinary sparse copies.

Each sandbox's `id` defaults to its position in name order and derives its network
addresses. Set `id` explicitly to keep them stable when adding or removing
other sandboxes. The host enables nftables and disables KSM. Unencrypted host swap
can contain guest memory; fencr warns when a swap device lacks
`randomEncryption`.

## checkpoints

On the host, as root:

```console
sudo fencr checkpoint myagent before-refactor
sudo fencr checkpoints myagent
sudo fencr restore myagent before-refactor
```

`restore` stops the sandbox and replaces its disk state. Read
[access and operation](access.md) for checkpoint retention and safe
inspection of state images.
