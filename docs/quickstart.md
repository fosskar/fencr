# quickstart

One sandbox for one workload. The host needs KVM and systemd-networkd.

```nix
# flake input
inputs.fencr.url = "github:fosskar/fencr";

# host configuration
imports = [ fencr.nixosModules.fencr ];
networking.useNetworkd = true;

fencr.sandboxes.myagent = {
  services = [ my-agent-module ];
  authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
};
```

Replace `my-agent-module` with your agent's NixOS module and the public key
with your own. Deploy with `nixos-rebuild`, then connect with `ssh myagent`.
fencr does not install or configure an agent for you.

With no further grants:

- the sandbox has no network egress, including DNS;
- the host can reach only its key-authenticated SSH listener;
- the whole guest filesystem persists across reboots and rebuilds, except
  that its read-only `/nix/store` image is replaced;
- each clean stop takes a disk checkpoint, retaining the last five.

## grant access

Add only the permissions the workload needs:

```nix
fencr.sandboxes.myagent = {
  outbound = [ "github.com" "*.github.com" "!gist.github.com" ];
  inbound = [ 9119 ];
};
```

Domains grant TLS on port 443. `"!name"` narrows a wildcard grant. You can
also grant an address and TCP port, `"192.168.1.50:8123"`, or a host port,
`"host:8080"`. Use `"internet"` instead of domain grants for public IPv4 access
and DNS; private networks remain blocked unless explicitly granted.

`inbound` opens guest TCP ports to **every host process**, not only your SSH
key. The service must listen on the guest's address, `fencr.sandboxes.myagent.ip`,
and provide any required authentication. It is not published to other machines.
See [network access](networking.md).

For a provider credential:

```nix
fencr.credentials.opencode-go.secretFile = "/run/secrets/opencode-go";
fencr.sandboxes.myagent.credentials = [ "opencode-go" ];
```

The host file contains just the API key. The guest gets an
`OPENCODE_GO_API_KEY` placeholder; the proxy inserts the real header.
The agent still needs to select OpenCode Go. See
[credentials and secrets](credentials.md) for other providers, Go and Zen
together, host commands and raw guest secrets.

For MCP tools, see the [optional gateway](mcp-gateway.md). It automatically
wires per-sandbox credentials, with explicit tool grants and host-side approvals
by default. Client-mediated same-chat approval is an explicit, less secure
opt-in; there is no bundled human approval UI.

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

## operate the sandbox

```console
fencr list
fencr status myagent
fencr checkpoint myagent before-refactor
fencr checkpoints myagent
fencr restore myagent before-refactor
```

`restore` stops the sandbox and replaces its disk state. Read
[access and operation](access.md) for SSH from other machines, checkpoint
retention and safe inspection of state images.
