# domain-allowlist egress via proxy

`allowedDomains` grants egress by name — "this vm may reach github.com and
nothing else". Firewalls cannot do that (rules match addresses, names
resolve to changing addresses), so like every agent sandbox that offers it,
fencr routes egress through a host-side proxy:

- setting it implies `egress = "closed"`; an explicit `egress = "open"`
  next to it is rejected, because a filtered proxy beside open egress is
  decoration
- a per-instance tinyproxy on host loopback is reachable only through a
  vsock hostForward — the road out has no IP path at all
- tinyproxy enforces the allowlist on the CONNECT hostname
  (`FilterType fnmatch`, `FilterDefaultDeny`) and permits CONNECT only on
  port 443; https needs no interception
- the proxy unit denies private, link-local, multicast and other special-use
  destination ranges, so an allowed hostname cannot grant LAN access by
  resolving to a private address
- the guest base exports `HTTP_PROXY`/`HTTPS_PROXY` system-wide and into
  `systemd.globalEnvironment`

A process that ignores the proxy variables is not a bypass: it hits the
closed firewall. Cooperation is the only way out, not a security
assumption.

## limits, stated plainly

- proxy-aware tools only. curl, git, pip, npm and nix honor the variables;
  raw sockets to arbitrary hosts stay dead by design
- fnmatch patterns: `*.github.com` does not match bare `github.com`; list
  both
- CONNECT is restricted to port 443; plain http rides ordinary proxying
- the allowlist names hosts, not paths or methods

## alternative considered

dnsmasq's `nftset=` can inject resolved addresses of allowlisted names
into an nftables set, giving transparent per-domain rules without proxy
variables. Rejected for now: shared CDN addresses make an accepted IP far
broader than the name that resolved to it, and cache churn makes the seal
racy. The proxy names the destination explicitly on every connection.
