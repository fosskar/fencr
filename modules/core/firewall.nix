{ lib, core, ... }:
let
  inherit (core)
    specialUseNetworks
    egressDnsPort
    egressTlsPort
    guestPortsOf
    forwardRules
    natRules
    redirectRules
    inputRules
    outputRules
    ;
  # `fencr status` sums these tags; a kind ending in blocked is a drop
  tag = cfg: kind: "fencr:${cfg.name}:${kind}";
  drop = cfg: match: kind: ''
    ${match} limit rate 5/second log prefix "${tag cfg kind}: "
    ${match} counter drop comment "${tag cfg kind}"
  '';
  # each chain counts its own, so the effective ceiling is up to twice this
  connectionCap =
    cfg:
    drop cfg ''iifname "${cfg.bridge}" ct state new ct count over ${toString cfg.maxConnections}''
      "connections-blocked";
in
{
  # what the guest reaches beyond the bridge
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
    ) cfg.destinations
    + "\n"
    + (
      if cfg.internet then
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

  redirectRules =
    cfg:
    lib.optionalString cfg.dnsEgress ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport 53 redirect to :${toString egressDnsPort}
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport 53 redirect to :${toString egressDnsPort}
    ''
    + lib.optionalString cfg.egress ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport 443 redirect to :${toString egressTlsPort}
    '';

  # what the guest reaches on the host itself. v6 is dropped first: the
  # host's own link-local multicast reflects off the bridge
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
    + lib.optionalString cfg.dnsEgress ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} udp dport ${toString egressDnsPort} counter accept comment "${tag cfg "dns"}"
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport ${toString egressDnsPort} counter accept comment "${tag cfg "dns-tcp"}"
    ''
    + lib.optionalString cfg.egress ''
      iifname "${cfg.bridge}" ip daddr ${cfg.hostIp} tcp dport ${toString egressTlsPort} counter accept comment "${tag cfg "egress-tls"}"
    ''
    + drop cfg ''iifname "${cfg.bridge}"'' "host-blocked";

  # what the host may open toward the guest
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

  # tables of their own so no host chain runs ahead of them, and one below
  # filter because a host chain at the same priority would tie
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
