# sandbox only, no agent

fencr ships the enclosure and nothing that runs inside it. The interface is
`services = [ <nixos modules> ]`; which agent those modules contain is the
user's business.

## context

The module was extracted from a private nixfiles repository where it hosted
hermes-agent instances. The agent wiring (channels, providers, secrets
generators, remote desktop) stays behind in that repository as the first
consumer.

## why

- shipping an agent means model configs, provider auth, and an update
  treadmill that has nothing to do with sandboxing
- the existing imperative sandboxes (E2B-style daemons and SDKs) compete on
  the runtime; fencr competes on being declarative NixOS — a substrate the
  daemon products cannot follow into
- a payload-agnostic interface is the proof the sandbox boundary is real:
  the module never needs to know what an agent is

## consequences

- examples may demonstrate running an agent, but demonstrate only
- feature requests shaped like "integrate provider X" are out of scope
