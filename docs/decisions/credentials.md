# credentials

Secrets reach a vm in one of two ways, and only one of them exposes the
value:

1. `secrets` passes host files through `fw_cfg` as systemd credentials. An
   early guest service materializes mode-0400 copies in the volatile
   `/run/agent-secrets`. The agent reads the real value. A prompt-injected
   agent can print it. The values never occupy persistent guest storage.
1. `fencr.credentials.<name>` never lets the value into the vm. The host
   declares the credential once: an `upstream` such as
   `https://api.anthropic.com`, the `header` it travels in, and the
   `secretFile` holding the raw header value. `fencr.vms.<vm>.credentials`
   grants it to a vm by name. Inside that vm the credential is one loopback
   port, `agentSandbox.credentials.<name>.port`; a payload module points
   its client there, for example
   `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`. The request crosses vsock,
   and a host-side proxy (caddy) injects the header and sends it on. The
   agent can use the credential but cannot read, log or exfiltrate it.

Prefer a granted credential for anything http. Use raw `secrets` only where
the payload needs the value itself (non-http protocols, client libraries
that insist on a key file).

## what a granted credential protects, stated plainly

The value, not the capability. An injected agent behind the proxy can still
call the API and do damage with it during the session; it cannot steal the
key for use elsewhere or leak it into logs and model context. Keys outlive
sessions, capabilities do not.

## shape

- one proxy unit per vm and credential, `<vm>-credential-<name>`: a caddy
  `reverse_proxy` with `header_up`, listening on a unix socket in its own
  runtime directory (`/run/fencr-credential-<vm>-<name>/credential.sock`,
  group `kvm`). the secret file is handed to the unit as a systemd
  credential; the unit runs as `DynamicUser`
- the proxy has no host loopback port. only members of group `kvm` reach
  its socket, and on a fencr host that is the cid-checked relay and the
  hypervisor units; another host process cannot borrow the credential
  through it
- an https upstream is tls the host originates. the guest never holds a
  certificate authority and nothing is intercepted: the guest speaks plain
  http to loopback, the hop is vsock, the host sees plaintext only for the
  credentials it was told about
- the upstream is loopback or the internet. the unit denies private and
  other special-use ranges, so an upstream name cannot resolve into the lan
- the guest port is `14000` plus the credential's index in
  `fencr.credentials`; the port names the units, and a repeated port is
  rejected like any other forward

## why not an intercepting proxy

Docker, Daytona, Blaxel and Vercel substitute a placeholder inside https
requests, which means terminating tls on the host with a certificate
authority the guest trusts. That makes any tool work unchanged, at the cost
of the proxy decrypting every allowed domain and of pinning clients
breaking. fencr's guest-visible surface is a base url, which every major
sdk honors, and the trust surface stays the size of the declared upstreams.

## not yet

- method or path scoping on an upstream. the proxy sees the request, so it
  is a matter of options, not mechanism
- a credential shared by several vms through one proxy process. today each
  grant is its own unit; the identity check is per relay either way
