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
  core = import ../../modules/core { inherit lib; };
  # a grant's text and where its use shows: a counted rule's tag, or the
  # proxy log's host lines for a domain pattern or a credential's domain
  grant = text: source: "Grant { text: ${builtins.toJSON text}, source: ${source} },";
  counted = text: tag: grant text ''Source::Counter("${tag}")'';
  ports = lib.concatMapStringsSep ", " toString;
  inbound =
    cfg:
    let
      opened = lib.unique (core.guestPortsOf cfg);
    in
    lib.optional (opened != [ ]) (
      counted (
        "TCP ${ports opened}" + lib.optionalString (lib.elem 22 opened && cfg.sshKeys != [ ]) " (22: ssh)"
      ) "guest"
    );
  outbound =
    cfg:
    lib.optional (cfg.egress == "open") (
      counted "public IPv4 internet and DNS (special-use ranges excluded)" "internet"
    )
    ++ lib.optional (cfg.hostPorts != [ ]) (counted "host TCP ${ports cfg.hostPorts}" "host")
    ++ map (
      destination:
      counted "${destination.address} TCP ${toString destination.port}" "pin-${destination.address}-${toString destination.port}"
    ) cfg.allowedTCPDestinations
    ++ map (domain: grant "${domain} TLS 443" ''Source::Domain("${domain}")'') cfg.allowedDomains
    ++ map (
      credential:
      grant "${credential.domain} TLS 443 (credential ${credential.name})" ''Source::Credential("${credential.domain}")''
    ) cfg.credentials;
  vmRow =
    name: cfg:
    ''Vm { name: "${name}", id: ${toString cfg.id}, cid: ${toString cfg.cid}, ip: "${cfg.ip}", host_ip: "${cfg.hostIp}", inbound: &[${lib.concatStrings (inbound cfg)}], outbound: &[${lib.concatStrings (outbound cfg)}], unit: "${units.${name}.unitNames.vm}" },'';

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
