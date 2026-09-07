{ lib, core, ... }:
let
  inherit (core)
    specialUseNetworks
    proxyDnsPort
    proxyTlsPort
    guestPortsOf
    forwardRules
    natRules
    redirectRules
    inputRules
    outputRules
    ;
in
{
  # forward chain: what the guest reaches beyond the bridge. egress "open":
  # dns and declared pinholes plus the internet, every other private range
  # dropped. egress "closed": nothing but the declared pinholes, dns
  # included in nothing. replies to whatever was allowed flow back either
  # way. counters and comments feed `fencr dashboard`; drops also log with a
  # rate limit so the journal shows who knocked without flooding
  forwardRules =
    cfg:
    let
      tag = kind: ''comment "fencr:${cfg.name}:${kind}"'';
      blocked = "{ ${lib.concatStringsSep ", " specialUseNetworks.v4} }";
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
          iifname "${cfg.bridge}" ip daddr ${blocked} limit rate 5/second log prefix "fencr-${cfg.name}-blocked: "
          iifname "${cfg.bridge}" ip daddr ${blocked} counter drop ${tag "blocked-private"}
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

  natRules = cfg: ''
    ip saddr ${cfg.ip} oifname != "${cfg.bridge}" masquerade
  '';

  # the guest talks to 53 and 443 on the bridge address; both go to ports
  # the egress proxy binds on that address alone
  redirectRules =
    cfg:
    lib.optionalString cfg.dnsProxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport 53 redirect to :${toString proxyDnsPort}
    ''
    + lib.optionalString cfg.proxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport 443 redirect to :${toString proxyTlsPort}
    '';

  # input chain: what the guest reaches on the host itself, the declared
  # ports and the egress proxy. v6 dropped first like on forward: the
  # host's own link-local multicast reflects off the bridge
  inputRules =
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

  # output chain: what the host itself may open toward the guest, its sshd
  # and its exposed ports and nothing else; replies to what the guest
  # opened flow back either way
  outputRules =
    cfg:
    let
      ports = guestPortsOf cfg;
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

  # the vm's firewall as complete nftables tables for
  # networking.nftables.tables. they stand on their own so no host chain
  # runs ahead of them; the filter chains sit one below filter, since a
  # host chain at the same priority would tie
  firewallOf = cfg: {
    "fencr-${cfg.name}-nat" = {
      family = "ip";
      content = ''
        chain prerouting {
          type nat hook prerouting priority dstnat; policy accept;
          ${redirectRules cfg}
        }
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          ${natRules cfg}
        }
      '';
    };
    "fencr-${cfg.name}" = {
      family = "inet";
      content = ''
        chain forward {
          type filter hook forward priority filter - 1; policy accept;
          ${forwardRules cfg}
          oifname "${cfg.bridge}" drop
        }
        chain input {
          type filter hook input priority filter - 1; policy accept;
          ${inputRules cfg cfg.hostPorts}
        }
        chain output {
          type filter hook output priority filter - 1; policy accept;
          ${outputRules cfg}
        }
      '';
    };
  };
}
