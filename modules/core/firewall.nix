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
  # every counted rule's comment and every drop's log prefix carry
  # "fencr:<vm>:<kind>", which `fencr status` sums and lists; a kind
  # ending in blocked is a drop
  tag = cfg: kind: "fencr:${cfg.name}:${kind}";
  drop = cfg: match: kind: ''
    ${match} limit rate 5/second log prefix "${tag cfg kind}: "
    ${match} counter drop comment "${tag cfg kind}"
  '';
  # the cap on connections the guest holds open, counted by conntrack on
  # the packets this rule sees: the guest's new connections on this
  # bridge, whichever chain they enter
  connectionCap =
    cfg:
    drop cfg ''iifname "${cfg.bridge}" ct state new ct count over ${toString cfg.maxConnections}''
      "connections-blocked";
in
{
  # forward chain: what the guest reaches beyond the bridge. egress "open":
  # declared pinholes plus the internet, every other private range
  # dropped. egress "closed": nothing but the declared pinholes. replies to
  # whatever was allowed flow back either way. drops log with a rate limit
  # so the journal shows who knocked without flooding
  forwardRules =
    cfg:
    let
      blocked = "{ ${lib.concatStringsSep ", " specialUseNetworks.v4} }";
    in
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
    ''
    + connectionCap cfg
    + lib.concatMapStringsSep "\n" (
      destination:
      ''iifname "${cfg.bridge}" ip daddr ${destination.address} tcp dport ${toString destination.port} counter accept comment "${tag cfg "pin-${destination.address}-${toString destination.port}"}"''
    ) cfg.allowedTCPDestinations
    + "\n"
    + (
      if cfg.egress == "open" then
        drop cfg ''iifname "${cfg.bridge}" ip daddr ${blocked}'' "private-blocked"
        + ''
          iifname "${cfg.bridge}" counter accept comment "${tag cfg "internet"}"
        ''
      else
        drop cfg ''iifname "${cfg.bridge}"'' "blocked"
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
  # ports, the host's resolver with open egress and the egress proxy. v6
  # dropped first like on forward: the host's own link-local multicast
  # reflects off the bridge
  inputRules =
    cfg:
    ''
      iifname "${cfg.bridge}" meta nfproto ipv6 drop
      iifname "${cfg.bridge}" ct state established,related accept
    ''
    + connectionCap cfg
    + lib.optionalString (cfg.hostPorts != [ ]) ''
      iifname "${cfg.bridge}" tcp dport { ${
        lib.concatMapStringsSep ", " toString cfg.hostPorts
      } } counter accept comment "${tag cfg "host"}"
    ''
    + lib.optionalString cfg.hostDns ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport 53 counter accept comment "${tag cfg "dns"}"
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport 53 counter accept comment "${tag cfg "dns-tcp"}"
    ''
    + lib.optionalString cfg.dnsProxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport ${toString proxyDnsPort} counter accept comment "${tag cfg "egress-dns"}"
    ''
    + lib.optionalString cfg.proxy ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport ${toString proxyTlsPort} counter accept comment "${tag cfg "egress-tls"}"
    ''
    + drop cfg ''iifname "${cfg.bridge}"'' "host-blocked";

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
      } } counter accept comment "${tag cfg "guest"}"
    ''
    + drop cfg ''oifname "${cfg.bridge}"'' "guest-blocked";

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
          ${inputRules cfg}
        }
        chain output {
          type filter hook output priority filter - 1; policy accept;
          ${outputRules cfg}
        }
      '';
    };
  };
}
