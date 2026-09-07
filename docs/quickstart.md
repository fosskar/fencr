# quickstart

One sealed vm for one agent. Everything else in this repo is optional.

```nix
# flake input
inputs.fencr.url = "github:fosskar/fencr";

# host configuration
imports = [ fencr.nixosModules.fencr ];

fencr.vms.myagent = {
  id = 0;
  services = [ my-agent-module ];                   # any nixos modules
  authorizedKeys = [ "ssh-ed25519 AAAA... you" ];   # ssh way in
  inbound = [ 9119 ];                               # web ui from the host
};
```

What this gives you, with no further options:

- the vm has no network egress, including dns
- nothing reaches the vm except `ssh myagent` (your key) and port 9119 at
  the vm's address (its web ui); the address is `fencr.vms.myagent.ip`
- the vm's disk survives reboots and rebuilds; only `/nix/store` is replaced
- 4 vcpus, 4 GiB with a hard cap the agent cannot exceed

Each further line is one permission or one limit:

```nix
  outbound = [ "github.com" "*.github.com" "192.168.1.50:8123" ];
  credentials = [ "anthropic" ];                      # api key the vm uses, never sees
  secrets."nostr.key" = "/run/secrets/nostr.key";     # a key the program must hold itself
  vcpu = 8; mem = 8192;                               # bigger box
```

Domain entries grant TLS on 443; address entries grant TCP on the stated
port. Add `"host:8080"` to reach a host service. For public internet and DNS
instead of selected domains, use `outbound = [ "internet" ];`. It can
accompany host/address entries, but not domains. Private networks remain
blocked unless explicitly granted. Replies need no separate grant.

`inbound` accepts integer TCP ports, reachable only from the host at the
vm's address; it does not publish them to other machines. `fencr status`
shows the effective grants, including automatic SSH and credential access.

Inside the vm, `services` entries are ordinary NixOS configuration:

```nix
  services = [
    my-agent-module
    { environment.systemPackages = [ pkgs.ripgrep pkgs.nodejs ]; }
  ];
```

Day-two reading, when a need appears and not before:

- [access.md](access.md) — ssh from other machines, the fencr command
- [decisions/credentials.md](decisions/credentials.md)
  — using an api without the key ever entering the vm
