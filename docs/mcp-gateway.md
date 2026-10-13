# MCP gateway

The optional host-side gateway gives each sandbox its own MCP tool permissions
without putting backend credentials in the guest. It does not use the egress
unit or the credential proxy: a sandbox reaches it over vsock, and the
socket a request arrives on names the sandbox.

```text
MCP client → guest 127.0.0.1:8764 → vsock port 7 → /run/fencr-<name>/vsock_7 → MCP gateway → host MCP backend
                                                   one socket per sandbox      checks tools   keeps service credentials
```

## configure backends and sandbox access

Both the gateway and per-sandbox access are disabled by default. An enabled
gateway needs at least one backend and one participating sandbox.

```nix
fencr.mcpGateway = {
  enable = true;
  servers.calendar = {
    url = "http://127.0.0.1:8765/mcp/";
    tokenFile = "/run/secrets/calendar-mcp-token";
    service = "calendar-mcp.service";
  };
};

fencr.sandboxes.myagent.mcp = {
  enable = true;
  allow = [ "calendar.list_events" ];
};
```

This assumes you already run a Streamable HTTP MCP backend exposing
`list_events`. fencr does not install the backend or provision its service
credentials. The optional `service` names an existing systemd unit that the
gateway requires and starts after. A backend that speaks stdio instead needs
no listener of its own; see [stdio backends](#stdio-backends).

Configure the agent's MCP client to use **`http://127.0.0.1:8764/mcp/`**,
including the trailing slash. Payloads read it as `agentSandbox.mcp.url`; the
port is `fencr.mcpGateway.port`. The payload still owns that application
setting. The client needs no token.

In the guest, `fencr-mcp.socket` listens on that loopback port and hands each
connection to `fencr-mcp@.service`, which forwards it to vsock port 7.
Firecracker delivers it to `/run/fencr-<name>/vsock_7` on the host, in the run
directory only the sandbox's own user enters, and `fencr-mcp-gateway.socket`
holds one such socket per participating sandbox. Every guest process can use
the loopback port. MCP needs no credential, no certificate authority and no
`outbound` grant, and works with `outbound = [ ]`.

## HTTP backends

A `url` backend must listen only on host IPv4 loopback and authenticate requests.
`url` must use `http://127.0.0.1:<port>/<path>`. `tokenFile` contains the backend's
bare bearer token; it can reference a Clan vars or other secret manager's
host file. Do not expose the backend on a bridge or grant its token separately
to a sandbox, which would let the guest bypass the gateway.

The gateway knows a backend only by its loopback port and sends the token to
whatever listens there. While the backend is down, restarting or not yet
started, any host user can bind that port, receive the token and answer in
the backend's place, with tool listings and results every participating
sandbox sees. Give the backend a port below 1024, or a systemd socket unit that
holds the port while the backend is down, or run it as a stdio backend.

## stdio backends

A backend that speaks MCP over stdin and stdout needs no port and no token:

```nix
fencr.mcpGateway.servers.time.command = [
  "${pkgs.mcp-server-time}/bin/mcp-server-time"
];
```

`command` replaces `url` and `tokenFile`; a backend sets one or the other.
The first element must be an absolute path.

fencr does not run the command inside the gateway. `fencr-mcp-backend-time.socket`
holds `/run/fencr-mcp/time.sock`, which only the gateway may connect to. For
each connection systemd starts `fencr-mcp-backend-time@.service` with that
connection as the command's stdin and stdout, so:

- each sandbox gets its own backend process, reused like an HTTP session and
  ended when the gateway closes it;
- the process runs under its own dynamic user and cannot read the gateway's
  backend tokens;
- no host user can take its place: pid 1 holds the socket even while no
  process runs.

The unit uses the same hardening as fencr's other host units, with no network
restriction. Add what the backend needs, such as credentials or network
limits, to its template:

```nix
systemd.services."fencr-mcp-backend-time@".serviceConfig = {
  LoadCredential = [ "api-key:/run/secrets/time-api-key" ];
  IPAddressDeny = "any";
};
```

The hardening includes `MemoryDenyWriteExecute`, which a JIT runtime such as
Node.js does not start under; set it to `false` there for such a backend.
The command's stderr goes to the journal of its instance unit.

## tool permissions

- `fencr.sandboxes.<name>.mcp.allow` contains `<server>.<tool>` globs, such as
  `calendar.list_events` or `calendar.*`. Empty means no tools.
- Both listing and invocation enforce that list. A guessed tool name does
  not bypass it.
- The MCP client sees names like `calendar__list_events`; policy uses
  `calendar.list_events`.
- `servers.<name>.hiddenTools` contains backend tool-name globs hidden from
  every sandbox and forbidden to call, regardless of `allow`.

The gateway does not ask for approval: a tool the list grants is called at
once. A wildcard such as `calendar.*` also grants tools the backend adds
later, so prefer explicit tool grants for tools that change things.

Each sandbox has a separate session registry. Reusing another sandbox's
MCP session ID is rejected, including requests to read or delete that session.

## backend connections

The gateway holds one connection to each backend per sandbox, reused for 30
seconds of idle time. A sandbox reuses only what it opened itself: a session is
keyed by sandbox and backend, never by backend alone, so it cannot carry one sandbox's
state to another.

A backend none of a sandbox's `allow` patterns can reach is never opened for
it, so a stdio backend runs only for the sandboxes granted some of its tools.
A pattern with a wildcard before its first dot, such as `*` or `cal*.read`,
counts as reaching every backend.

Connections open on first use, not at startup, so a backend that is down
cannot keep the gateway from starting and every MCP-enabled sandbox from its
other backends. An idle session is dropped and remade on the next
call, so a restarted backend needs no intervention. A tool listing that fails
runs once more on a fresh session; a tool call does not, because the backend
may have acted before the failure. It fails, and the next call opens a fresh
session.

## operation

Inspect the host units:

```console
systemctl status fencr-mcp-gateway.service
journalctl -u fencr-mcp-gateway.service
```

The gateway logs every tool call and refused tool name as
`<sandbox>: called <server>.<tool>` or `<sandbox>: refused '<name>'`.
`fencr status` does not list MCP requests.

pid 1 holds every sandbox's socket while the gateway restarts, so a restart
loses sessions but no sandbox loses its way in.

After rotating a `url` backend's `tokenFile`, update the backend as needed and
restart `fencr-mcp-gateway.service` so systemd reloads the credential. Restarting
the gateway interrupts active sessions; clients must reconnect.

Host root and the backend implementations remain trusted. Host-held tokens do not make every permitted tool safe, or stop a
backend from disclosing information in its own results.
