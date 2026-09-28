# MCP gateway

The optional host-side gateway gives each sandbox its own MCP tool permissions
without putting backend credentials in the guest. It is separate from the
HTTP credential proxy: the proxy injects a header; the gateway decides which
tools may be listed or called.

```text
agent sandbox → HTTPS credential proxy → MCP gateway → host MCP backend
           adds the sandbox's token      checks tools   keeps service credentials
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
gateway requires and starts after.

Backends must listen only on host IPv4 loopback and authenticate requests.
`url` must use `http://127.0.0.1:<port>/<path>`. `tokenFile` contains the backend's
bare bearer token; it can reference a Clan vars or other secret manager's
host file. Do not expose the backend on a bridge or grant its token separately
to a sandbox, which would let the guest bypass the gateway.

The gateway knows a backend only by its loopback port and sends the token to
whatever listens there. While the backend is down, restarting or not yet
started, any host user can bind that port, receive the token and answer in
the backend's place, with tool listings and results every participating
sandbox sees. Give the backend a port below 1024, or a systemd socket unit that
holds the port while the backend is down.

Configure the agent's MCP client to use **`https://mcp.fencr/mcp/`**, including
the trailing slash. The payload still owns that application setting. No real
bearer token is needed in the guest; if the client requires one, a dummy value
is sufficient because the proxy replaces the authorization header.

fencr automatically creates and grants a separate `mcp-<sandbox-name>` credential
for each participating sandbox. No manual `fencr.credentials` declaration or
`outbound` host-port grant is needed. The gateway listens on host loopback
port 8764 by default, configurable through `fencr.mcpGateway.port`.

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

Each sandbox has a separate authenticated session registry. Reusing another sandbox's
MCP session ID is rejected, including requests to read or delete that session.

## backend connections

The gateway holds one connection to each backend per sandbox, reused for 30
seconds of idle time. A sandbox reuses only what it opened itself: a session is
keyed by sandbox and backend, never by backend alone, so it cannot carry one sandbox's
state to another.

Connections open on first use, not at startup, so a backend that is down
cannot keep the gateway from starting and every MCP-enabled sandbox from its
other backends. An idle session is dropped and remade on the next
call, so a restarted backend needs no intervention. A tool listing that fails
runs once more on a fresh session; a tool call does not, because the backend
may have acted before the failure. It fails, and the next call opens a fresh
session.

## credentials and operation

Per-sandbox gateway credentials are generated on the host under
`/var/lib/fencr-mcp/` and retained across service restarts. systemd delivers
only the required credentials to each egress proxy and the gateway. MCP
credentials have `substitutePlaceholder = false`, so a tool argument cannot
cause the proxy to insert the real token into data the tool might echo.

Their `allow` is `[ "* /mcp/" ]`. A credential's `upstream` is an origin, so
without that entry the sandbox's token would be injected into a request for any
path the gateway's port serves; pinning the path keeps it to the one route the
gateway mounts. The methods are deliberately not pinned. The MCP transport
chooses those, and it rejects the ones it does not use itself — listing them
here would only refuse a method a later transport revision starts relying on,
and the symptom would be a 403 in `fencr status` rather than an obvious break.

Inspect the host units:

```console
systemctl status fencr-mcp-gateway.service
journalctl -u fencr-mcp-gateway.service
journalctl -u fencr-myagent-egress.service
```

`fencr status myagent` shows HTTP requests through the credential proxy; it
is not a tool-level audit log.

After rotating a backend's `tokenFile`, update the backend as needed and
restart `fencr-mcp-gateway.service` so systemd reloads the credential. Restarting
the gateway interrupts active sessions; clients must reconnect.

Host root and the backend implementations remain trusted. Host-held tokens do not make every permitted tool safe, or stop a
backend from disclosing information in its own results.
