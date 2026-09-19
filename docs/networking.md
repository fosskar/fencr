# network access

`inbound` defaults to empty: nothing on the host reaches the VM until a port
is named. `outbound` defaults to `[ "internet" ]`, which is public IPv4 and
DNS with private and other special-use ranges still blocked. Setting
`outbound` replaces that default rather than adding to it, so an allowlist
needs no opt-out, and `outbound = [ ]` leaves the VM no egress at all,
including DNS. SSH keys and credentials automatically open their required
paths; `fencr status` shows those alongside explicit grants. Reply traffic
needs no separate grant.

```nix
fencr.vms.myagent = {
  inbound = [ 8080 ];
  outbound = [
    "github.com"
    "*.github.com"
    "!gist.github.com"
    "host:8123"
    "192.168.20.0/24:1234"
  ];
};
```

## inbound ports

`inbound` lists guest TCP ports the host may reach at `fencr.vms.<name>.ip`.
The service must listen on the VM's address, not only on guest loopback.
These ports are not published to the LAN or internet.

**An inbound grant does not authenticate clients.** Every host process can
connect to the port. Use application authentication for services that need it.
SSH has its own key authentication; see [access](access.md).

## outbound grants

| Entry | Effect |
| --- | --- |
| `"github.com"` | TLS on port 443 to that server name. No port suffix. |
| `"*.github.com"` | TLS on port 443 to subdomains, not bare `github.com`. |
| `"!gist.github.com"` | Refuses a name a wildcard grant would otherwise admit. |
| `"host:8123"` | TCP to port 8123 on the host, over the VM's bridge. |
| `"192.168.20.0/24:1234"` | TCP to an IPv4 address or subnet and port, including private destinations. |
| `"internet"` | Public IPv4 internet access and DNS. Private and other special-use ranges remain blocked unless explicitly granted. |

`"internet"` can accompany host/address grants, but not domain grants.
A deny entry must narrow an existing wildcard grant; it cannot equal a grant
or name something no grant covers. IPv6 is blocked on the bridge.

A `host:` grant reaches the host on any address the guest can route to over
the bridge — its bridge address and its LAN addresses — but never its
loopback listeners, which the guest has no route to. One exception: on the
bridge address, port 443 belongs to the VM's egress unit, which the firewall
redirects it to, so `"host:443"` only ever reaches the host's other
addresses. For a host-loopback HTTP API with credentials, use a
[credential proxy](credentials.md#custom-apis); for MCP tools, use the
[optional gateway](mcp-gateway.md).

## what domain grants enforce

Domain grants inspect TLS Server Name Indication (SNI), not HTTP paths or
methods. They do not decrypt the traffic and need no proxy environment
variables. Plain HTTP and TLS connections without a visible server name
are not supported by these grants.

Shared CDN infrastructure can allow a client to reach a different site
through an allowed server name. Domain grants are not application-level
request filtering. [Credential `allow` rules](credentials.md#limiting-api-use)
and [MCP tool permissions](mcp-gateway.md#tool-permissions) operate at those
higher levels.

## DNS

Where DNS is enabled, the VM's own egress unit is its resolver. With domain
grants it answers names with the bridge address, then judges the destination
from the TLS handshake. With `"internet"` it relays queries to the host's stub
resolver, with a limit on concurrent queries. The guest does not reach the
host's systemd-resolved listener directly.

Once the egress resolver is enabled, port 53 to other resolvers is refused
and shown as `dns-blocked`. An explicit destination grant, such as
`"192.168.10.5:53"`, permits TCP DNS to that resolver. Encrypted DNS is TLS on
port 443: `"internet"` cannot distinguish it from other HTTPS traffic, while
a domain allowlist can exclude known resolver names.

See the [domain egress decision record](decisions/domain-egress-proxy.md)
for design history.
