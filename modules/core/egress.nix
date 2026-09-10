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

  # high ports the firewall redirects the guest's 53 and 443 to, so a host
  # service on *:443 or *:53 is no conflict and the proxy binds unprivileged
  proxyDnsPort = 33053;
  proxyTlsPort = 33443;

  egressProxyBin = pkgs: pkgs.callPackage ../../pkgs/egress-proxy { };

  egressProxyServiceConfig =
    pkgs: instance:
    proxyHardening
    // {
      ExecStart = "${egressProxyBin pkgs}/bin/fencr-egress-proxy ${instance.hostIp}:${toString proxyDnsPort} ${instance.hostIp}:${toString proxyTlsPort} ${
        pkgs.writeText "fencr-egress-domains" (
          lib.concatMapStrings (domain: "${domain}\n") instance.domains
        )
      } ${
        pkgs.writeText "fencr-egress-denied" (lib.concatMapStrings (domain: "${domain}\n") instance.denied)
      } ${
        pkgs.writeText "fencr-egress-intercepts" (
          lib.concatMapStrings (credential: "${credential.domain}\n") instance.credentials
        )
      } ${credentialSocketOf instance}";
      # checked before proxyHardening's deny list, so it names only what that
      # would otherwise take; the internet needs no entry
      IPAddressAllow = [
        "127.0.0.53/32"
        instance.subnet
      ];
    };
}
