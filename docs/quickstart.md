# quickstart

One sealed vm for one agent. Everything else in this repo is optional.

```nix
# flake input
inputs.fencr.url = "github:fosskar/fencr";

# host configuration
imports = [ fencr.nixosModules.fencr ];

fencr.vms.myagent = {
  id = 0;
  services = [ my-agent-module ];                    # any nixos modules
  authorizedKeys = [ "ssh-ed25519 AAAA... you" ];    # ssh way in
  expose = [ "22100" ];                              # web ui way in
};
```

What this gives you, with no further options:

- the vm has no network egress, including dns
- nothing reaches the vm except `ssh myagent` (your key, over vsock) and
  host port 22100 (its web ui)
- `/var/lib` inside the vm survives reboots and rebuilds
- 4 vcpus, 4 GiB with a hard cap the agent cannot exceed

Each further line is one permission or one limit:

```nix
  allowedDomains = [ "github.com" "*.github.com" ];  # out: only these sites
  allowedTCPDestinations = [ "192.168.1.50:8123" ];  # out: one address
  egress = "open";                                    # out: public internet
  credentials = [ "anthropic" ];                      # api key the vm uses, never sees
  vcpu = 8; mem = 8192;                               # bigger box
```

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
