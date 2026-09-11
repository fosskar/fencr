# credentials

How a secret a vm needs reaches the place it is used without the vm ever
holding it. This is the history of that mechanism: two designs on one day,
what each was chosen for, and what turned the first into the second.
Nothing here is a rule.

## the two ways in, and what stays true across both

- `fencr.credentials.<name>` declares a credential once on the host: an
  `upstream` such as `https://api.anthropic.com`, the `header` it travels
  in, and the `secretFile` holding the raw header value.
  `fencr.vms.<vm>.credentials` grants it to a vm by name. The vm's egress
  unit on the host injects the header; the value never exists
  inside the vm. An injected agent behind the proxy can still
  call the api and do damage with it during the session; it cannot steal
  the key for use elsewhere or leak it into logs and model context. Keys
  outlive sessions, capabilities do not
- `fencr.vms.<vm>.secrets` is the second way, for a key a program must
  hold itself and only for that: host files copied into the vm's volatile
  `/run/agent-secrets`, mode 0400, fetched over vsock at boot. Removing it
  was considered on 2026-09-06 and rejected on the facts of one real agent:
  a Nostr signing key, a Matrix recovery key and a token for a service on
  the lan have no header to ride in. An http api key is never a `secrets`
  entry; it is a credential
- nothing on the host can borrow a credential: the only door is the vm's
  own bridge address, which the firewall opens to that vm alone. The unit
  denies private ranges, so an upstream name cannot resolve into the lan.
  An https upstream is tls the host originates
- `allow` entries scope a credential by method and path since 2026-09-10;
  every request it rides on is on record. Not yet: a credential shared by
  several vms through one proxy process; a secret that must sit in a URL
  or a body rather than a header (issue 26); a value resolved from a
  command or a vault at use time rather than read from `secretFile` at
  unit start (issue 25)

## 2026-09-06, morning: a loopback port in the guest

The first design gave the guest one loopback port per credential,
`agentSandbox.credentials.<name>.port`, 14000 plus the credential's index,
speaking plain http through a vsock forward to the proxy. A payload module
pointed its client there, `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`.

Chosen because the guest then held no certificate authority and nothing was
intercepted: the guest spoke plain http to loopback, the hop was vsock, the
host saw plaintext only for the credentials it was told about. Docker,
Daytona, Blaxel and Vercel substitute a placeholder inside https requests,
which means terminating tls on the host with an authority the guest trusts;
this design refused that at the cost of every client needing to be pointed
at the port.

What that cost turned out to be, on the first real payload: hermes takes a
base url per provider through its own environment variables and refuses a
provider without a key present, so the payload had to carry a table of
providers with their api roots and a placeholder key, and every further
client would need its own such table. The credential, declared once in
fencr, had to be described a second time on the guest side.

## 2026-09-06, evening: tls interception for the credential's domain

The design now in the code. The guest calls the credential's domain as it
would anywhere. Inside the vm the name resolves to the host through
`/etc/hosts`; on the bridge the egress proxy reads the server name from the
client hello and hands the connection to the vm's caddy on its unix
socket, which holds a certificate for each granted domain from a per-host
authority, ends the tls, replaces the header and sends the request on.

- one caddy per vm, `fencr-<vm>-credentials.service`, holding every credential
  granted to that vm. It began as one unit per vm and credential, so a
  bug in one proxy would expose one secret; dropped the same day, since
  the vm can use every credential granted to it anyway and the extra
  units separated nothing the vm could not reach. Two vms never share a
  process
- one authority per host, `fencr-ca.service`, made on first use with
  openssl in `/var/lib/fencr/ca`, a directory root alone reads. The
  credential unit gets the root as systemd credentials and signs a
  certificate for each domain with it. A vm with a credential fetches
  the root certificate beside its secrets at boot and rebuilds the system
  trust store in `/run/fencr`: the store bundle with the authority
  appended, on every path the bundle sits on. Python's certifi and node
  carry bundles of their own, so `NIX_SSL_CERT_FILE` and
  `NODE_EXTRA_CA_CERTS` are set for sessions and services
- what a credential's `domain` is: the upstream's host by default. An
  upstream on host loopback has no name a vm could call, so it needs one
  set, `mcp.fencr` say, and the option refuses an ip or `localhost`
- the egress proxy runs for every vm with a credential. With
  `allowedDomains` it was already the guest's resolver and the road out;
  with a credential alone the guest keeps its own resolver and only the
  tls listener opens, in the vm's firewall and in the host firewall. The
  dns pinhole stays tied to `allowedDomains`. Both listeners sit on high
  ports of the bridge address that the firewall redirects 53 and 443 to, so
  a host serving `*:443` itself, as nixbox does, is no conflict
- the vsock forwards for credentials, the guest ports, the relay's unix
  target and `agentSandbox.credentials` went away. The guest contract
  carries `credentialDomains` instead
- accepted costs: the host reads every request to a credential's domain,
  and only those; a client that pins the upstream's real certificate cannot
  use a credential; a client that ignores both the system store and the two
  variables fails with a certificate error on that domain. A client that
  insists on a key still needs a placeholder, as it does behind Docker's
  and the others' proxies; that is the client's rule, not fencr's
- the boot check calls `https://api.test/` from the guest without
  `--insecure` and sees the header replaced; the authority is trusted
  without the test saying so

## 2026-09-10: what the proxy sees, it records and may refuse

The credential proxy ends the tls, so it holds each request in the clear
for the moment it forwards it. Two things followed from that, both
compared against Docker Sandboxes, Claude Code's sandbox and Coder's
`boundary`, which all sit in the same place:

- `fencr.credentials.<name>.allow` lists `"<methods> <path>"` entries,
  `"GET,HEAD *"`, `"POST /repos/*/pulls"`. The caddyfile renders one
  matcher and handle per entry and answers 403 itself for the rest, so a
  refused request never reaches the upstream. Empty keeps every request
  admitted. A github token can then open pull requests and read, and not
  delete a repository, whatever the token itself allows. For a model
  provider with one endpoint it changes nothing
- caddy's access log writes one json record per request to the journal,
  method, host, path and status, with request and response headers
  filtered out since the guest's own header sits there. `fencr status`
  aggregates them under "Credential requests". Before this the only trace
  was the egress proxy's `intercept <host>` line, which says a connection
  went in and nothing about what it carried

The same day the shell wrapper that read each secret into a
`FENCR_CREDENTIAL_<n>` environment variable went: caddy's `{file.<path>}`
placeholder reads the credential file at request time, strips the one
trailing newline a secret file carries, and `{$CREDENTIALS_DIRECTORY}` is
filled in when the caddyfile is parsed. The secret no longer sits in the
process environment.

## 2026-09-10: a rotated secretFile reaches the proxy

`LoadCredential` copies a credential's `secretFile` into the unit's
credentials directory once, when the proxy starts, so a token that expires
in an hour was unusable: the value stayed until someone restarted the unit.
Caddy already reads the credential per request (the `{file.}` placeholder
above), so the only thing frozen was that copy.

A `.path` unit watches every `secretFile` on the host and starts a oneshot
that runs `systemctl try-restart` on the credential proxies. Two units for
the host, not two per vm: a path unit can only start a unit, never restart
one, so something has to do the restarting, and rotation is rare enough
that one watcher for all of them beats a pair per vm. The cost is that
rotating one credential restarts the proxies of every vm that has one,
dropping their in-flight requests for the moment it takes.

The boot check writes a new value into the credential file and sees the
guest's next request carry it, with nothing restarted by hand.

Not yet: a value fetched at use time rather than read from a file — `gh auth token`, `op read`, an STS call (issue 25). systemd's `LoadCredential`
accepts an `AF_UNIX` socket as its source, so a socket-activated provider
would keep the value off disk and out of the store; the refresh interval
would then be systemd's, not fencr's.

## 2026-09-10: a placeholder the guest may carry

A payload had to invent a dummy key per provider, which is what sank the
first credential design (above: hermes needed "a table of providers with
their api roots and a placeholder key"). fencr now supplies one:
`placeholderOf` derives `fencr-<24 hex>` from the vm and the credential
name, so it is stable across rebuilds, differs per vm, and is no secret —
it may sit in the store. The guest gets it in
`agentSandbox.credentialPlaceholders`, and in an environment variable when
the credential names one with `guestEnv`.

What the proxy does with it: `uri replace <placeholder> {file …}` before
the reverse proxy, so a credential can ride in the query of an api that
takes no header. The header is still overwritten unconditionally, as
before, so nothing that works today changes.

Two limits, both measured rather than assumed:

- caddy's `uri replace` reaches the path and the query, not the body.
  Substituting inside a request body needs a handler caddy does not have;
  that is the rest of issue 26, and it decides whether the credential proxy
  stays caddy or becomes a second rust program
- a value with a space in it produces an invalid request line when it lands
  in a uri. The boot check saw the upstream answer 400 for
  `?key=Bearer fencr-api-token`. The placeholder in a uri is for uri-safe
  values; a header carries anything

Not taken yet: refusing to inject unless the placeholder is present. It
would mean a request the payload did not mark — a library's telemetry, a
stray call from an injected agent — no longer gets the credential for free.
It is not a boundary against the agent, which can read the placeholder from
its own environment, but it makes intent explicit and a misdirected
placeholder visible. It needs the matchers to carry a header condition
beside the `allow` entries, and it would refuse traffic that works today,
so it wants its own decision.

## 2026-09-11: one go program, and then one process

Caddy went. It was 85 MiB of closure and 25 MiB resident to terminate tls
and rewrite one header, and the body substitution the placeholder needed
was a handler it does not have. `pkgs/egress` is a go program whose whole
dependency tree is the standard library — `crypto/tls`, `crypto/x509` for
the certificate per domain, `httputil.ReverseProxy` — so it packages with
`vendorHash = null` like the rust ones, and its closure is 10 MiB. It does
what the caddyfile did, and what caddy could not: substitute inside a
request body, bounded at 1 MiB, larger or unmeasured bodies forwarded
untouched. `FlushInterval = -1` keeps server-sent events flowing, which an
mcp gateway needs.

Then the two proxies became one. The vm's connection used to cross a unix
socket from the egress proxy to the credential proxy; now one process
reads the client hello and either splices the connection onward or ends it
itself. What that removed is the point:

- no socket between two host processes, so no `Group = "kvm"` on the unit
  and no runtime directory to protect. The socket existed only because
  two processes had to meet
- one unit per vm, `fencr-<vm>-egress.service`, one journal, one process.
  `fencr status` reads one journal for both the connection verdicts and
  the credential requests
- little isolation was traded for it. Both units already denied every
  special-use range and both already reached the public internet, since an
  upstream is out there; the merged unit adds the guest's own subnet,
  which is where it listens

The cost is that a fault in the tls termination now sits in the same
process as the splice for every other name. The splice never parses what
it carries, so the blast radius is a crash, and `Restart = always` covers
that; a second process would not have made the parser safer.
