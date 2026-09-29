# quickstart

One sandbox for one workload.

Two machines appear below, and they can be the same one:

- **the host** is the NixOS machine you add fencr to. It builds and runs the
  sandboxes, and every command on this page runs there unless it says
  otherwise;
- **your machine** is where you sit, if that is somewhere else, such as a
  laptop.

## what the host needs

- KVM, on `x86_64-linux` or `aarch64-linux`;
- `systemd.network.enable = true`, which `networking.useNetworkd = true` sets.
  The sandbox's bridge and tap are networkd units; fencr checks for networkd
  rather than switching the host's networking over itself;
- systemd-resolved, which networkd turns on by default.

## 1. add fencr to the host's flake

In the host's `flake.nix`, add the input and the module:

```nix
{
  inputs.fencr.url = "github:fosskar/fencr";

  outputs = { nixpkgs, fencr, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        fencr.nixosModules.fencr
      ];
    };
  };
}
```

## 2. declare a sandbox

In the host's `configuration.nix`:

```nix
networking.useNetworkd = true;

fencr.sandboxes.myagent = {
  services = [ my-agent-module ];
  authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
  outbound = [ ];
};
```

- `services` holds ordinary NixOS modules that run inside the sandbox. Put
  your agent's module there; fencr does not install or configure an agent.
- `authorizedKeys` holds the public SSH keys allowed into this sandbox. The
  matching private key stays wherever you run `ssh` from.
- `outbound = [ ]` closes all network access, DNS included; only
  `credentials` and MCP access, added later, open their own domains. Leaving
  `outbound` unset gives the sandbox the public internet instead; see
  [grant access](#grant-access).

## 3. deploy

On the host:

```console
sudo nixos-rebuild switch --flake .#myhost
```

This builds the sandbox and starts it, and installs the `fencr` command on the
host.

## 4. connect

**On the host**, as the user holding the private key for `authorizedKeys`:

```console
ssh myagent
```

This works because fencr adds a `Host myagent` entry to the host's SSH
configuration, pointing at the sandbox's private address. You land as root
inside the sandbox.

**From your machine**, the sandbox's address is private to the host, so SSH
jumps through it. Add this to `~/.ssh/config` on your machine, with the
address `fencr list` prints on the host:

```
Host myagent
  HostName 10.11.0.2
  User root
  ProxyJump fencr-jump-myagent@myhost
```

Then `ssh myagent` works from your machine too. The jump account can open a
connection to this one sandbox and do nothing else on the host; see
[access and operation](access.md).

## 5. look at it

On the host:

```console
fencr list                     # every sandbox with its address and grants
sudo fencr status myagent      # health, grants in use, blocked traffic
```

`fencr list` and `fencr ssh` work as any user. Everything else reads the
firewall, the journal or the sandbox's state and needs root.

With `outbound = [ ]`, no `credentials` and no `mcp.enable`:

- the sandbox reaches nothing outside itself, DNS included. A credential or
  MCP access still reaches its own domain through the host's egress unit,
  even with `outbound = [ ]`;
- the host reaches only its SSH listener, and only with a key from
  `authorizedKeys`;
- the whole guest filesystem persists across reboots and rebuilds, except
  that its read-only `/nix/store` image is replaced;
- each clean stop takes a disk checkpoint, retaining the last five.

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
