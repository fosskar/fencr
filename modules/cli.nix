# the fencr command: read-only convenience over the declared instances.
# mutation stays with nixos-rebuild. the instance table is baked at eval,
# so the binary needs no manifest and no daemon. the program is cli.rs;
# this file appends the tables and tool paths it reads
{
  lib,
  pkgs,
  instances,
  units,
}:
let
  core = import ./core { inherit lib; };
  rustStringSlice = values: "&[" + lib.concatMapStringsSep ", " builtins.toJSON values + "]";
  inbound =
    cfg:
    map (
      port:
      "TCP ${toString port}"
      + lib.optionalString (port == 22 && cfg.sshKeys != [ ]) " (SSH; authorized keys)"
    ) (lib.unique (core.guestPortsOf cfg));
  outbound =
    cfg:
    lib.optional (cfg.egress == "open") "public IPv4 internet and DNS (special-use ranges excluded)"
    ++ map (port: "host TCP ${toString port}") cfg.hostPorts
    ++ map (
      destination: "${destination.address} TCP ${toString destination.port}"
    ) cfg.allowedTCPDestinations
    ++ map (domain: "${domain} TLS 443") cfg.allowedDomains
    ++ map (
      credential: "${credential.domain} TLS 443 (credential ${credential.name}; key stays on host)"
    ) cfg.credentials;
  vmRow =
    name: cfg:
    ''Vm { name: "${name}", id: ${toString cfg.id}, cid: ${toString cfg.cid}, ip: "${cfg.ip}", inbound: ${rustStringSlice (inbound cfg)}, outbound: ${rustStringSlice (outbound cfg)}, unit: "${units.${name}.unitNames.vm}" },'';

  proxiedRows = name: unitSet: map (unit: ''("${name}", "${unit}"),'') unitSet.unitNames.proxy;

  credentialRows =
    name: unitSet: map (unit: ''("${name}", "${unit}"),'') unitSet.unitNames.credentials;
in
pkgs.writers.writeRustBin "fencr"
  {
    rustcArgs = [
      "-O"
      "--edition"
      "2024"
    ];
  }
  (
    builtins.readFile ./cli.rs
    + ''
      static VMS: &[Vm] = &[
      ${lib.concatStrings (lib.mapAttrsToList vmRow instances)}
      ];

      // vm, egress proxy unit
      static PROXIED: &[(&str, &str)] = &[
      ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList proxiedRows units))}
      ];

      // vm, credential unit
      static CREDENTIALS: &[(&str, &str)] = &[
      ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList credentialRows units))}
      ];

      const SSH: &str = "${pkgs.openssh}/bin/ssh";
      const SYSTEMCTL: &str = "${pkgs.systemd}/bin/systemctl";
      const JOURNALCTL: &str = "${pkgs.systemd}/bin/journalctl";
      const NFT: &str = "${pkgs.nftables}/bin/nft";
    ''
  )
