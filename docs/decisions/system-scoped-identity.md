# system-scoped, not user-scoped

fencr runs as a system-wide systemd service and assumes no invoking user.
It owns the hypervisor, the vsock transport and the vms independent of any
login session, keychain or `SSH_AUTH_SOCK`. Identity arrives per connection
as an ssh public key, from any client — a human, CI, or another machine.

## the hub shape

The machine running the vms is a hub. Clients attach to it and authenticate
per connection by key; the hub owns the vms and any resident credentials.
The hub is whichever machine runs the vms — a server, a VPS, or a personal
workstation. It need not be always on and it need not have a logged-in user.

## contrast with docker sbx

`sbx` is deliberately user-scoped: it runs per user and draws identity from
that user's session — the shell environment, the forwarded agent, the OS
keychain, `~/.config`. The sandbox is an extension of one logged-in human's
workstation identity.

fencr makes the opposite choice, and the rest of the design follows from it:

- there is no ambient user agent or keychain to lean on, so credentials that
  must stay out of a vm are held on the hub and proxied (see
  `credentials.md`), not read from a user session
- ssh agent forwarding, where offered, is a property of a client's
  connection, not of the service; it serves connected sessions and cannot
  serve an autonomous agent running while nobody is attached
- there is no ambient user checkout, so a working tree is never a repository
  source; getting code into a vm is payload, not enclosure (see
  `sandbox-only-scope.md`)

## consequences

- a vm belongs to whoever holds an authorized key, not to a system account
- the same model serves humans, CI and machines without any of them existing
  as a linux user on the hub
- host root still reaches every vm through the hypervisor regardless of keys;
  that is the boundary, not a user relationship
