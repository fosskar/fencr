# credentials and secrets

Use `credentials` when the host can authenticate an API request on the VM's
behalf. Use `secrets` only when the workload must hold the real value itself.
Never put real secret contents in a Nix expression or the Nix store.

## provider presets

Declare a host credential and grant it to a VM:

```nix
fencr.credentials.anthropic = {
  secretFile = "/run/secrets/anthropic";
  guestEnv = "ANTHROPIC_API_KEY";
};
fencr.vms.myagent.credentials = [ "anthropic" ];
```

The file contains **just the API key**, without quotes, JSON or an environment
variable assignment. A trailing newline is fine. The workload still chooses
its provider and calls the provider's normal API URL.

A credential's name selects a matching preset automatically. Use
`provider = "openrouter";` to select one under a different credential name.

| Preset | Injected header | Default `guestEnv` |
| --- | --- | --- |
| `anthropic` | `x-api-key: <key>` | None |
| `openai` | `Authorization: Bearer <key>` | None |
| `openrouter` | `Authorization: Bearer <key>` | None |
| `opencode` | `Authorization: Bearer <key>` | None |
| `opencode-go` | `Authorization: Bearer <key>` | `OPENCODE_GO_API_KEY` |
| `opencode-zen` | `Authorization: Bearer <key>` | `OPENCODE_ZEN_API_KEY` |

Bearer presets also accept existing values containing `Bearer <key>` without
adding the prefix twice. Without a provider, or when overriding its header
with a different header name, supply the complete header value instead.

`guestEnv` names a guest environment variable containing a **placeholder**,
not the real key. It satisfies clients that require a key to start; it does
not choose the client's provider. Payload modules can also read placeholders
from `specialArgs.agentSandbox.credentialPlaceholders`.

## secret sources

`secretFile` refers to a host file. It can be a secret manager's output,
including a Clan vars file:

```nix
fencr.credentials.openai.secretFile =
  config.clan.core.vars.generators.openai.files.key.path;
```

This references an existing generator and file; fencr does not create them.
Use the file's path, not its contents. Changes to credential files trigger a
restart of the affected credential proxies through the host's reload unit;
that unit restarts all proxies with credentials, interrupting in-flight requests.

Use `secretCommand` instead when the value comes from a command:

```nix
fencr.credentials.openrouter.secretCommand = [
  "/run/current-system/sw/bin/resolve-openrouter-key"
];
```

`resolve-openrouter-key` is an example host-provided executable, not a fencr
command. It must print the key in the same format as `secretFile`.
Give a credential exactly one source: `secretFile` or `secretCommand`.

The command runs non-interactively on the host as an isolated systemd
`DynamicUser`, not your logged-in user. An `rbw get` command therefore does
not automatically have access to your unlocked vault or session. Configure
that access separately or use a non-interactive secret source.

systemd reads the command's output through a socket when the VM's egress unit
starts; fencr does not write it to a secret file. Restarting
`fencr-<name>-egress.service` resolves it again. A failed or empty result
prevents startup; there is no last-known-good fallback.

## OpenCode Go and Zen

Go and Zen use different API paths and credentials on the same domain.
Both can be granted to one VM:

```nix
fencr.credentials.opencode-go.secretFile = "/run/secrets/opencode-go";
fencr.credentials.opencode-zen.secretFile = "/run/secrets/opencode-zen";
fencr.vms.myagent.credentials = [ "opencode-go" "opencode-zen" ];
```

The client uses `https://opencode.ai/zen/go/v1` for Go and
`https://opencode.ai/zen/v1` for Zen. Their placeholder environment variables
are supplied automatically. The presets use `https://opencode.ai` as the
upstream origin, preserving the client's path and query rather than adding
the API path again.

Their default `allow` entries are `"* /zen/go/v1/*"` and `"* /zen/v1/*"`.
For multiple credentials on one domain, every credential needs non-empty
`allow` entries. Exactly one credential must match a request; zero or multiple
matches return 403. Order never selects a key.

The legacy `opencode` preset has no path restrictions. Do not combine it with
the distinct presets on one VM without giving it non-overlapping `allow` entries.

## custom APIs

Set the upstream and header explicitly:

```nix
fencr.credentials.example = {
  upstream = "https://api.example.com";
  header = "x-api-key";
  secretFile = "/run/secrets/example";
};
```

The header defaults to `Authorization`; without a provider, its file must
contain the full value, such as `Bearer <key>` or `Basic <value>`.
For a host-loopback API, set an HTTP upstream and the name the VM will call:

```nix
fencr.credentials.local-api = {
  upstream = "http://127.0.0.1:8765";
  domain = "api.fencr";
  secretFile = "/run/secrets/local-api-authorization";
};
```

The guest calls `https://api.fencr`. Do not include the client's API base path
in `upstream` unless you intend it to be prepended to forwarded requests.

## limiting API use

A credential authorizes whatever the upstream key can do. Narrow that with
HTTP method/path rules:

```nix
fencr.credentials.github = {
  upstream = "https://api.github.com";
  secretFile = "/run/secrets/github-authorization";
  allow = [
    "GET,HEAD *"
    "POST /repos/*/pulls"
  ];
};
```

Rules use `"<methods> <path>"`. Methods are comma-separated, or `*` for any
method. A path's `*` matches any characters, including `/`. An empty `allow`
list allows every request for that credential; provider presets may set a
narrower default. Unmatched requests receive 403 without reaching upstream.
`fencr status` shows request methods, paths and status codes, not headers.

The header is injected either way, so most credentials need nothing further.
`substitutePlaceholder = true` additionally replaces the placeholder in
request URIs and known-length bodies up to 1 MiB — **enable it only for an
API that takes the key in a query parameter or a body field.** It is off by
default because a client can put its placeholder into data that an API echoes
or stores, disclosing the real credential in a response the guest reads; URI
substitutions also appear in request logs. Keeping keys on the host is not a
guarantee against disclosure by the APIs you allow the guest to call.

## transport and trust

The credential's domain resolves to the host inside the VM. The egress proxy
terminates TLS using a per-host certificate authority trusted by the guest,
injects the header and forwards the request. The guest receives the public
CA certificate, not its private key. fencr configures the system trust store,
`NIX_SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`; certificate-pinning clients
cannot use this interception path.

HTTP method/path rules do not understand MCP tools. Use the separate
[MCP gateway](mcp-gateway.md) for tool-level permissions and approvals.

## raw guest secrets

```nix
fencr.vms.myagent.secrets."agent.env" = "/run/secrets/agent.env";
```

The host file is fetched over vsock at boot into
`/run/agent-secrets/agent.env`, readable by guest root. Unlike a credential,
this value is available to a compromised guest. It is useful for secrets
that cannot be handled by a proxy, such as a signing key.

See the [credential decision record](decisions/credentials.md) for design history.
