# credential brokering

Secrets reach a vm in one of two ways, and only one of them exposes the
value:

1. `secrets` passes host files through QEMU `fw_cfg` as systemd
   credentials. An early guest service materializes mode-0400 copies in the
   volatile `/run/agent-secrets`. The agent reads the real value. A
   prompt-injected agent can print it. The values never occupy a host share or
   persistent guest storage.
1. `hostForwards.*.broker` never lets the value into the vm: the guest
   speaks plain http to its loopback proxy, the connection crosses vsock,
   and a host-side proxy (caddy) injects the configured header from a file
   loaded via systemd `LoadCredential`. The agent can use the capability
   but cannot read, log or exfiltrate the credential.

Prefer the broker for anything http. Use raw `secrets` only where the
payload needs the value itself (non-http protocols, client libraries that
insist on a key file).

## what the broker protects, stated plainly

The credential value, not the capability. An injected agent behind the
broker can still call the API and do damage with it during the session; it
cannot steal the key for use elsewhere or leak it into logs and model
context. Keys outlive sessions, capabilities do not.

## v0 shape and its edges

- one broker per brokered hostForward: a caddy `reverse_proxy` with
  `header_up`, listening on a declared host loopback port
- the secret file holds the raw header value (for example `Bearer x`);
  it is handed to the unit as a systemd credential, the unit runs as
  `DynamicUser`
- the broker listens on host loopback tcp, so other host processes could
  reach it and act with the injected credential. acceptable on a
  single-operator host; a unix-socket listener with peer credentials is
  the hardening step if this assumption breaks
- http only. tls-originating forward proxies for external apis are out of
  scope for v0 and belong to the same roadmap line as name-based egress
  rules
