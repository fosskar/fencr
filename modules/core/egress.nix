{ lib, core, ... }:
let
  inherit (core)
    proxyHardening
    specialUseNetworks
    domainPatternError
    egressProxyBin
    credentialSocketOf
    forwardFilterFragment
    hostToGuestFragment
    natRuleFragment
    proxyRedirectFragment
    proxyDnsPort
    proxyTlsPort
    sealInputFragment
    ;
in
{

  # domain-allowlist egress: the guest's resolver is the bridge address,
  # where the egress proxy answers every name with itself, so every tls
  # connection lands on the host and is judged by the server name in its
  # client hello; an allowed name is passed through unread
  dnsProxyOf = cfg: cfg.allowedDomains != [ ];

  # the same listener takes the credentials' domains, which the guest's
  # /etc/hosts points at the bridge: by server name the proxy hands the
  # connection to that credential's caddy, which holds the certificate
  proxyOf = cfg: cfg.allowedDomains != [ ] || cfg.credentials != [ ];

  # the guest talks to 53 and 443 on the bridge address; the seal's nat
  # table redirects both to ports the proxy binds on that address alone,
  # so a host service on *:443 or *:53 is no conflict and the proxy needs
  # no capability to bind
  proxyDnsPort = 33053;
  proxyTlsPort = 33443;

  # a pattern is a hostname, optionally with a leading "*." label. anything
  # else is rejected: "*github.com" also matches evilgithub.com, and stray
  # fnmatch metacharacters widen the allowlist silently.
  domainPatternError =
    pattern:
    if builtins.match "(\\*\\.)?([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+" pattern != null then
      null
    else if lib.hasPrefix "*" pattern && !lib.hasPrefix "*." pattern then
      "\"${pattern}\": a wildcard must be its own label (\"*.example.com\"); \"*example.com\" also matches evilexample.com"
    else
      "\"${pattern}\": not a hostname pattern; expected \"example.com\" or \"*.example.com\"";

  domainPatternErrors = domains: lib.filter (e: e != null) (map domainPatternError domains);

  egressProxyBin =
    pkgs:
    pkgs.writers.writeRustBin "fencr-egress-proxy" {
      rustcArgs = [
        "-O"
        "--edition"
        "2024"
      ];
    } ./egress-proxy.rs;

  # listens on the bridge address only, so the guest's subnet is allowed in
  # beside the internet; every other private range stays denied, and an
  # allowed name resolving into the lan goes nowhere. group kvm is what
  # the credential proxies' sockets admit
  egressProxyServiceConfig =
    pkgs: instance:
    proxyHardening
    // {
      ExecStart = "${egressProxyBin pkgs}/bin/fencr-egress-proxy ${instance.hostIp}:${toString proxyDnsPort} ${instance.hostIp}:${toString proxyTlsPort} ${
        pkgs.writeText "fencr-egress-domains" (
          lib.concatMapStrings (domain: "${domain}\n") instance.allowedDomains
        )
      } ${
        pkgs.writeText "fencr-egress-intercepts" (
          lib.concatMapStrings (
            credential: "${credential.domain} ${credentialSocketOf instance}\n"
          ) instance.credentials
        )
      }";
      Group = "kvm";
      # resolving on the host goes through resolved, over its unix socket
      # or its stub on 127.0.0.53
      IPAddressAllow = [
        "0.0.0.0/0"
        "::/0"
        "127.0.0.53/32"
        instance.subnet
      ];
      IPAddressDeny = specialUseNetworks.v4 ++ specialUseNetworks.v6;
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
      ];
    };

  # forward-chain fragment sealing a bridge. egress "open": dns and declared
  # pinholes plus the internet, every other private range dropped. egress
  # "closed": nothing but the declared pinholes, dns included in nothing.
  # replies to whatever was allowed flow back either way.
  # counters and comments feed `fencr dashboard`; drops also log with a
  # rate limit so the journal shows who knocked without flooding
  forwardFilterFragment =
    cfg:
    let
      tag = kind: ''comment "fencr:${cfg.name}:${kind}"'';
      sealed = "{ ${lib.concatStringsSep ", " specialUseNetworks.v4} }";
    in
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
    ''
    + lib.optionalString (cfg.egress == "open") ''
      iifname "${cfg.bridge}" ip daddr ${cfg.dns} udp dport 53 counter accept ${tag "dns"}
      iifname "${cfg.bridge}" ip daddr ${cfg.dns} tcp dport 53 counter accept ${tag "dns-tcp"}
    ''
    + lib.concatMapStringsSep "\n" (
      destination:
      ''iifname "${cfg.bridge}" ip daddr ${destination.address} tcp dport ${toString destination.port} counter accept ${tag "pin-${destination.address}-${toString destination.port}"}''
    ) cfg.allowedTCPDestinations
    + "\n"
    + (
      if cfg.egress == "open" then
        ''
          iifname "${cfg.bridge}" ip daddr ${sealed} limit rate 5/second log prefix "fencr-${cfg.name}-blocked: "
          iifname "${cfg.bridge}" ip daddr ${sealed} counter drop ${tag "blocked-private"}
          iifname "${cfg.bridge}" counter accept ${tag "internet"}
        ''
      else
        ''
          iifname "${cfg.bridge}" limit rate 5/second log prefix "fencr-${cfg.name}-blocked: "
          iifname "${cfg.bridge}" counter drop ${tag "blocked"}
        ''
    )
    + ''
      oifname "${cfg.bridge}" ct state established,related accept
    '';

  natRuleFragment = cfg: ''
    ip saddr ${cfg.ip} oifname != "${cfg.bridge}" masquerade
  '';

  proxyRedirectFragment =
    cfg:
    lib.optionalString cfg.dnsProxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport 53 redirect to :${toString proxyDnsPort}
    ''
    + lib.optionalString cfg.proxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport 443 redirect to :${toString proxyTlsPort}
    '';

  # input-chain fragment sealing the vms' host access to the declared ports;
  # v6 dropped first like on forward: the host's own link-local multicast
  # reflects off the bridge
  sealInputFragment =
    cfg: ports:
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
      iifname "${cfg.bridge}" ct state established,related accept
    ''
    + lib.optionalString (ports != [ ]) ''
      iifname "${cfg.bridge}" tcp dport { ${
        lib.concatMapStringsSep ", " toString ports
      } } counter accept comment "fencr:${cfg.name}:host"
    ''
    + lib.optionalString cfg.dnsProxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport ${toString proxyDnsPort} counter accept comment "fencr:${cfg.name}:egress-dns"
    ''
    + lib.optionalString cfg.proxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport ${toString proxyTlsPort} counter accept comment "fencr:${cfg.name}:egress-tls"
    ''
    + ''
      iifname "${cfg.bridge}" limit rate 5/second log prefix "fencr-${cfg.name}-host-blocked: "
      iifname "${cfg.bridge}" counter drop comment "fencr:${cfg.name}:host-blocked"
    '';

  # output-chain fragment: what the host itself may open toward the guest.
  # the guest's sshd and its exposed ports, nothing else; replies to what
  # the guest opened flow back either way
  hostToGuestFragment =
    cfg:
    let
      ports = lib.optional (cfg.sshKeys != [ ]) 22 ++ cfg.expose;
    in
    ''
      oifname "${cfg.bridge}" meta nfproto ipv6 drop
      oifname "${cfg.bridge}" ct state established,related accept
    ''
    + lib.optionalString (ports != [ ]) ''
      oifname "${cfg.bridge}" ip daddr ${cfg.ip} tcp dport { ${
        lib.concatMapStringsSep ", " toString ports
      } } counter accept comment "fencr:${cfg.name}:guest"
    ''
    + ''
      oifname "${cfg.bridge}" limit rate 5/second log prefix "fencr-${cfg.name}-guest-blocked: "
      oifname "${cfg.bridge}" counter drop comment "fencr:${cfg.name}:guest-blocked"
    '';

  # the seal as complete nftables tables for networking.nftables.tables. they
  # stand on their own so no host chain runs ahead of them; the chains sit
  # one below filter, since a host chain at the same priority would tie
  firewallOf = cfg: {
    "fencr-${cfg.name}-nat" = {
      family = "ip";
      content = ''
        chain prerouting {
          type nat hook prerouting priority dstnat; policy accept;
          ${proxyRedirectFragment cfg}
        }
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          ${natRuleFragment cfg}
        }
      '';
    };
    "fencr-${cfg.name}" = {
      family = "inet";
      content = ''
        chain forward {
          type filter hook forward priority filter - 1; policy accept;
          ${forwardFilterFragment cfg}
          oifname "${cfg.bridge}" drop
        }
        chain input {
          type filter hook input priority filter - 1; policy accept;
          ${sealInputFragment cfg cfg.hostPorts}
        }
        chain output {
          type filter hook output priority filter - 1; policy accept;
          ${hostToGuestFragment cfg}
        }
      '';
    };
  };
}
