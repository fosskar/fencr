# fencr

<div align="center">

*Sealed Firecracker microVM sandboxes for AI agents on NixOS*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![NixOS flake](https://img.shields.io/badge/NixOS-flake-5277C3?style=flat-square&logo=nixos&logoColor=white)](flake.nix)
[![Firecracker](https://img.shields.io/badge/Firecracker-microVM-FF9900?style=flat-square)](https://firecracker-microvm.github.io/)

[Overview](#overview) • [Features](#features) • [How it works](#how-it-works) • [Getting started](#getting-started) • [Security](#security) • [Documentation](#documentation)

</div>

______________________________________________________________________

## Overview

fencr is a NixOS module that runs an AI agent inside a Firecracker microVM and
keeps control of what that VM can do outside itself. Each sandbox is a full
NixOS guest with its own kernel, its own disk and an unprivileged host user.
Nothing from the host is mounted into it.

An agent writes and runs its own commands. On your own machine that means it
can read every file you can, reach everything on your network, and spend your
API keys. A VM ends the file access. It does not end the other two: the VM
still has a network, and the key is still inside it.

fencr moves those two decisions to the host:

- **Outbound traffic is denied unless you grant the destination**, and the
  grant is enforced by a host process the guest cannot configure.
- **API keys stay on the host.** The guest holds a placeholder; the host puts
  the real key into the requests you permitted, and only those.
- **MCP tool calls go through a gateway** that can require approval before a
  tool runs.

Built on [microvm.nix](https://github.com/microvm-nix/microvm.nix).

> [!NOTE]
> fencr ships no agent, clones no repositories and mounts no working tree. You
> supply the agent as a NixOS module; fencr supplies the sandbox and the
> boundary around it.

*Pronounced **fencer** /ˈfɛnsər/ — "fence" + "er".*

## Features

- **Credentials the guest never holds.** The host injects the real key into
  requests whose method and path you allowed, answers the rest with 403, and
  replaces the key with the placeholder on the way back. Presets for Anthropic,
  OpenAI, OpenRouter and OpenCode Go/Zen; secret files, Clan vars and host
  commands as sources.
- **MCP tool permissions.** Put existing MCP servers behind one gateway that
  grants tools per sandbox and runs an approval command you supply before a
  tool executes — allow calendar lookups, require approval to create events.
  Backend tokens stay on the host.
- **Outbound access you grant by name.** Sandboxes get public IPv4 and DNS by
  default, with the LAN and other special-use ranges closed. Narrow that to
  named domains, IP/port pairs or host ports, or to nothing at all.
- **Inbound only from the host.** Guest ports you list are reachable from host
  processes. Nothing is published to the LAN.
- **Persistent state and checkpoints.** The guest's disk survives reboots and
  rebuilds. Copies are taken on clean stops, on a schedule or on demand, and
  `fencr restore` puts one back.
- **Per-sandbox limits.** CPU, memory, disk size, disk and network bandwidth,
  and concurrent connections.
- **Visibility from one command.** `fencr status` reports which grants were
  used, what was blocked and why, and every API request the host proxied.

## How it works

A sandbox is a block in your NixOS configuration:

```nix
fencr.credentials.anthropic = {
  secretFile = "/run/secrets/anthropic";
  allow = [ "POST /v1/messages" ];
};

fencr.vms.myagent = {
  authorizedKeys = [ "ssh-ed25519 AAAA... you" ];
  inbound = [ 9119 ];
  outbound = [ "github.com" "*.github.com" "!gist.github.com" ];
  credentials = [ "anthropic" ];
  services = [ ./my-agent.nix ];
};
```

`nixos-rebuild` turns that into a microVM, a bridge, a set of nftables tables
and one host process that is the sandbox's only road out. From inside the
guest:

1. Every DNS query goes to that process. A name you granted answers with the
   host's bridge address; nothing leaves the machine.
1. The connection is matched by the TLS server name and, if a grant covers it,
   passed onward without being opened.
1. A credential's domain is the exception. The host answers the TLS itself,
   checks the method and path against `allow`, adds the real key and forwards
   the request upstream.
1. Anything else is dropped, counted and logged.

Afterwards, `fencr status` shows what the sandbox actually did:

```console
$ fencr status myagent
myagent  RUNNING  10.11.0.2  memory 412M
VMM: Running
Inbound (from host):
  ✓ TCP 22, 9119 (22: ssh)                    3 packets
Outbound (otherwise denied):
  ✓ github.com TLS 443                        4 connections
  · *.github.com TLS 443                      unused
  ✓ !gist.github.com TLS 443 (denied)         1 connection
  ✓ api.anthropic.com TLS 443 (credential anthropic)  6 connections

Blocked (journal, rate-limited sample):
  ✗ guest → gist.github.com:443/tls   x1     denied by outbound "!gist.github.com"
  ✗ guest → pypi.org:443/tls          x3     outbound "pypi.org"

Credential requests (journal):
  POST api.anthropic.com/v1/messages → 200  x6
  POST api.anthropic.com/v1/complete → 403  x1

Services: egress RUNNING
```

The agent asked for `pypi.org` three times and never got there; the hint is the
grant that would let it. It also called `/v1/complete`, which `allow` does not
cover, so the host answered 403 without the key ever leaving.

## Getting started

### Requirements

- A NixOS host with KVM, on `x86_64-linux` or `aarch64-linux`
- `networking.useNetworkd = true` — the bridge and tap are networkd units, and
  fencr asserts this rather than switching your host's networking underneath
  you

### Add the flake

```nix
inputs.fencr.url = "github:fosskar/fencr";
```

### Declare a sandbox

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

Replace the key, put your agent's module in `services`, and deploy with
`nixos-rebuild`.

### Use it

```console
ssh myagent
fencr status myagent
```

Your agent's module reads its own contract — address, inbound ports,
credential domains and placeholders — from `specialArgs.agentSandbox`, so it
needs no fencr-specific configuration of its own.

## Security

The host is the trust root. fencr defends the host and your credentials
against the guest, in that order.

> [!IMPORTANT]
> Host root is trusted and reaches every sandbox. SSH into a sandbox grants
> guest root — that is the intended privilege level, not a weakness. `inbound`
> ports are open to every host process and do not authenticate; the guest
> service must do that itself.

> [!WARNING]
> Keeping a key on the host does not limit what the allowed API can do with it.
> `allow` narrows a credential to methods and paths, but any request that
> matches is made with the real key. If the upstream echoes a request back, the
> host replaces the key with the placeholder in response headers and in bodies
> up to 1 MiB; a streamed or unmeasured body is passed through untouched.

> [!WARNING]
> The MCP gateway has no approval UI. Under the default `approvalMode = "host"`
> you supply `approvalCommand`, and a missing, failing or slow command denies
> the call. `approvalMode = "client"` asks the requesting client instead, which
> means a compromised client can approve its own calls.

fencr is early. The interfaces here work and are covered by the checks in
`checks/`, up to a guest booting under nested KVM, but options may still
change.

## Documentation

| Guide | What it covers |
| --- | --- |
| [How fencr works](docs/overview.md) | The units, the road out and what is refused where |
| [Quickstart](docs/quickstart.md) | Creating a sandbox, defaults and resource limits |
| [Network access](docs/networking.md) | Inbound ports, egress grants and their limits |
| [Credentials and secrets](docs/credentials.md) | Provider presets, files, commands and OpenCode Go/Zen |
| [MCP gateway](docs/mcp-gateway.md) | Tool permissions, host approvals and in-chat prompts |
| [Access and operation](docs/access.md) | SSH, status, checkpoints and restore |

Design rationale lives in the [decision records](docs/decisions/).
