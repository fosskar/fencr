# MCP gateway

The optional host-side gateway gives each sandbox its own MCP tool permissions
without putting backend credentials in the guest. It is separate from the
HTTP credential proxy: the proxy injects a header; the gateway decides which
tools may be listed or called and whether a call needs approval.

```text
agent sandbox → HTTPS credential proxy → MCP gateway → host MCP backend
           adds the sandbox's token      checks tools   keeps service credentials
                                   and approval
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

Configure the agent's MCP client to use **`https://mcp.fencr/mcp/`**, including
the trailing slash. The payload still owns that application setting. No real
bearer token is needed in the guest; if the client requires one, a dummy value
is sufficient because the proxy replaces the authorization header.

fencr automatically creates and grants a separate `mcp-<sandbox-name>` credential
for each participating sandbox. No manual `fencr.credentials` declaration or
`outbound` host-port grant is needed. The gateway listens on host loopback
port 8764 by default, configurable through `fencr.mcpGateway.port`.

**The example grants tool access but does not yet approve calls.** Every tool
requires approval by default. Configure host approval or explicitly opt into
client elicitation below before calling it. You can also relax approval for
tools you have reviewed as safe.

## tool permissions

- `fencr.sandboxes.<name>.mcp.allow` contains `<server>.<tool>` globs, such as
  `calendar.list_events` or `calendar.*`. Empty means no tools.
- Both listing and invocation enforce that list. A guessed tool name does
  not bypass it.
- The MCP client sees names like `calendar__list_events`; policy uses
  `calendar.list_events`.
- `servers.<name>.hiddenTools` contains backend tool-name globs hidden from
  every sandbox and forbidden to call, regardless of `allow`.
- `servers.<name>.approvalTools` contains backend tool-name globs needing
  approval through `approvalMode`. It defaults to `[ "*" ]`; an empty list removes approval
  requirements for that backend, not its per-sandbox allowlist.

For a backend with known tools, you can restrict `approvalTools` to its
write/effectful tools. That is a host policy decision: a newly added tool
outside those patterns will not need approval if an `allow` pattern grants
it. Prefer explicit tool grants over broad wildcards.

Each sandbox has a separate authenticated session registry. Reusing another sandbox's
MCP session ID is rejected, including requests to read or delete that session.

## approval modes

`fencr.mcpGateway.approvalMode` defaults to `"host"`, which requires a trusted
host executable. `"client"` explicitly opts into MCP form elicitation for
same-chat approval where the client supports it. There is no automatic
fallback between modes. `approvalTimeout` applies to both.

### host approval (default)

Configure a trusted host executable:

```nix
fencr.mcpGateway.approvalCommand = [
  "/run/current-system/sw/bin/approve-mcp"
];
fencr.mcpGateway.approvalTimeout = 120;
```

`approve-mcp` is an example of an executable **you provide**, not a bundled
fencr command or UI. For each approval-required call, the gateway passes one
JSON object on stdin:

```json
{
  "principal": "myagent",
  "server": "calendar",
  "tool": "create_event",
  "arguments": { "summary": "Team meeting", "calendar": "Personal" }
}
```

The gateway supplies the principal, tool and full arguments; the agent does
not write an approval summary. Exit status 0 approves that invocation only.
Nonzero exit, launch failure, timeout or no configured command denies it
without executing the tool. The default timeout is 120 seconds.

The command runs as the gateway's isolated host user, with a minimal
environment, no interactive login session and loopback-only IP access.
Use absolute executable paths. Stdout is ignored; stderr goes to the journal,
so do not print secrets or sensitive arguments there.

A suitable implementation connects to a separate authenticated host-side
approval service over a Unix socket or loopback. Its UI should:

- display the gateway's exact principal, tool and arguments as untrusted text;
- authenticate the human independently of the guest and agent;
- bind the decision to one pending invocation, not a reusable blanket approval;
- reject expired requests and never reuse an earlier approval.

A desktop notification can be a front end to that service. A guest-accessible
confirmation endpoint or a command that always exits 0 is not independent
human approval. The gateway provides the enforcement interface, not this UI.

### client elicitation (same-chat opt-in)

To restore client-mediated approval during migration:

```nix
fencr.mcpGateway.approvalMode = "client";
```

Remove any `approvalCommand` setting when selecting this mode. For each
protected tool call, the gateway sends an MCP form elicitation containing
the exact principal, tool and full arguments, associated with that call.
Only an explicit `accept` response authorizes execution. Decline, cancellation,
errors, unsupported form elicitation and timeout deny the call.

A supporting client can show this prompt in the same chat session. **fencr
does not control the client's UI**: verify the actual Hermes integration
before deploying the migration. A client without elicitation support cannot
use approval-protected tools in this mode.

**Client approval is not independent human authorization.** The gateway trusts
the requesting MCP client to ask you; a compromised client can accept its own
requests. This mode can prevent accidental actions in a trusted client, but
weakens protection compared with host approval. Enabling it emits a NixOS
configuration warning. Tool allowlists, credential isolation and cross-principal
session restrictions remain enforced.

## backend connections

The gateway holds one connection to each backend per sandbox, reused for 30
seconds of idle time. A sandbox reuses only what it opened itself: a session is
keyed by sandbox and backend, never by backend alone, so it cannot carry one sandbox's
state to another.

Connections open on first use, not at startup, so a backend that is down
cannot keep the gateway from starting — every MCP-enabled sandbox's egress unit
requires the gateway, and a broken backend would otherwise take that sandbox off
the network entirely. An idle session is dropped and remade on the next
call, so a restarted backend needs no intervention, and a call that fails
runs once more on a fresh session.

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
is not a tool-level approval audit log. The approval service should keep its
own decision record if one is required.

After rotating a backend's `tokenFile`, update the backend as needed and
restart `fencr-mcp-gateway.service` so systemd reloads the credential. Restarting
the gateway interrupts active sessions; clients must reconnect. Gateway
restarts also restart the participating sandboxes' egress proxies.

Host root, the approval command and the backend implementations remain
trusted. Host-held tokens do not make every permitted tool safe, or stop a
backend from disclosing information in its own results.
