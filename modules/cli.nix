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
  vmRow =
    name: cfg:
    ''("${name}", ${toString cfg.id}, ${toString cfg.cid}, "${cfg.ip}", "${cfg.egress}", ${toString (lib.length cfg.allowedDomains)}, "${units.${name}.unitNames.vm}"),'';

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
      // name, id, cid, ip, egress, allowed domain count, vm unit
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
