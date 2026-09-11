# credentials

How a secret a vm needs reaches the place it is used without the vm ever
holding it. This is the history of that mechanism: two designs on one day,
what each was chosen for, and what turned the first into the second.
Nothing here is a rule.

## the two ways in, and what stays true across both

- `fencr.credentials.<name>` declares a credential once on the host: an
  `upstream` such as `https://api.anthropic.com`, the `header` it travels
  in, and the `secretFile` holding the raw header value.
  `fencr.vms.<vm>.credentials` grants it to a vm by name. A host-side
  caddy, one unit per vm, injects the header; the value never exists
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
- the proxy has no host loopback port. It listens on a unix socket in its
  own runtime directory, group `kvm`, so nothing else on the host can
  borrow the credential through it. The unit denies private ranges, so an
  upstream name cannot resolve into the lan. An https upstream is tls the
  host originates
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
  credential unit gets the root as systemd credentials and lets caddy's
  internal issuer sign each domain's leaf. A vm with a credential fetches
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
