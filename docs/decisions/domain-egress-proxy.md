# domain-allowlist egress by server name

`allowedDomains` grants egress by name — "this vm may reach github.com and
nothing else". Firewalls cannot do that (rules match addresses, names
resolve to changing addresses), so fencr judges each connection by the
name the client itself puts in the tls handshake:

- setting it implies `egress = "closed"`; an explicit `egress = "open"`
  next to it is rejected, because a filtered road beside open egress is
  decoration
- the vm's resolver is the host's bridge address. There the egress proxy
  answers every A query with that same address and everything else with
  an empty answer, so no dns query leaves the host and every tls
  connection the guest opens lands on the host
- on port 443 of the bridge address the proxy reads the server name
  indication from the client hello, checks it against the allowlist,
  resolves the allowed name with the host's resolver, connects, and
  splices the bytes through unread. Nothing is decrypted and the guest
  holds no certificate authority
- the proxy unit denies private, link-local, multicast and other
  special-use destination ranges, so an allowed hostname cannot grant lan
  access by resolving to a private address
- the seal's input chain admits only dns and 443 from the bridge to the
  host; a raw address on 443 hits the closed forward chain

No proxy variables in the guest, no cooperation required: a tool that
ignores nothing and simply connects is judged the same as curl.

## limits, stated plainly

- tls only. Plain http, and any protocol that is not tls with a server
  name, has no road out. `allowedTCPDestinations` remains for addresses
- `*.github.com` does not match bare `github.com`; list both
- the allowlist names hosts, not paths or methods; a granted credential
  is where request-level scoping belongs (`credentials.md`)
- encrypted client hello hides the server name; such a connection has no
  name and is refused
- a client may say one name in the handshake and another inside the
  encrypted request. On a shared cdn address that reaches a different site
  than the allowlist named; the same holds for every sandbox that
  enforces by server name

## earlier shape, replaced

A per-vm tinyproxy on host loopback, reached over a vsock forward, with
`HTTP_PROXY`/`HTTPS_PROXY` exported into the guest. It enforced the
allowlist on the CONNECT hostname and worked only for tools that honor the
variables; everything else hit the closed firewall. Replaced because
enforcement by server name needs no cooperation and removes the proxy
variables, the vsock forward and tinyproxy.

## alternative considered

dnsmasq's `nftset=` can inject resolved addresses of allowlisted names
into an nftables set, giving transparent per-domain rules. Rejected:
shared cdn addresses make an accepted address far broader than the name
that resolved to it, and cache churn makes the seal racy. The server name
names the destination explicitly on every connection.
