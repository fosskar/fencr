{ lib, core, ... }:
let
  inherit (core)
    proxyHardening
    egressProxyBin
    credentialSocketOf
    proxyDnsPort
    proxyTlsPort
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

  # the guest talks to 53 and 443 on the bridge address; the firewall's
  # nat table redirects both to ports the proxy binds on that address
  # alone, so a host service on *:443 or *:53 is no conflict and the
  # proxy needs no capability to bind
  proxyDnsPort = 33053;
  proxyTlsPort = 33443;

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
  # beside the internet
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
      # resolving on the host goes through resolved, over its unix socket
      # or its stub on 127.0.0.53
      IPAddressAllow = [
        "0.0.0.0/0"
        "::/0"
        "127.0.0.53/32"
        instance.subnet
      ];
    };
}
