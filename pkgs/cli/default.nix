# the instance table is baked in at eval, so the binary needs no manifest
# and no daemon; the program is cli.rs
{
  lib,
  pkgs,
  instances,
}:
let
  core = import ../../modules/core { inherit lib; };
  # a grant's text and where its use shows
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
    lib.optional cfg.internet (
      counted "public IPv4 internet and DNS (special-use ranges excluded)" "internet"
    )
    ++ lib.optional (cfg.hostPorts != [ ]) (counted "host TCP ${ports cfg.hostPorts}" "host")
    ++ map (
      destination:
      counted "${destination.address} TCP ${toString destination.port}" "pin-${destination.address}-${toString destination.port}"
    ) cfg.destinations
    ++ map (domain: grant "${domain} TLS 443" ''Source::Domain("${domain}")'') cfg.domains
    ++ map (domain: grant "!${domain} TLS 443 (denied)" ''Source::Denied("${domain}")'') cfg.denied
    ++ map (
      credential:
      grant "${credential.domain} TLS 443 (credential ${credential.name})" ''Source::Credential("${credential.domain}")''
    ) cfg.credentials;
  vmRow =
    name: cfg:
    ''Vm { name: "${name}", id: ${toString cfg.id}, ip: "${cfg.ip}", host_ip: "${cfg.hostIp}", inbound: &[${lib.concatStrings (inbound cfg)}], outbound: &[${lib.concatStrings (outbound cfg)}], unit: "${(core.unitsOf name).vm}.service", checkpoint_unit: "${(core.unitsOf name).checkpoint}@", state_dir: "${core.stateDirOf name}" },'';

  # the journal the command reads, and whether a credential writes to it
  proxiedRows =
    name: cfg:
    lib.optional cfg.egress ''("${name}", "${(core.unitsOf name).egress}.service", ${
      if cfg.credentials != [ ] then "true" else "false"
    }),'';
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
    + builtins.readFile ../domain.rs
    + ''
      static VMS: &[Vm] = &[
      ${lib.concatStrings (lib.mapAttrsToList vmRow instances)}
      ];

      // vm, proxy unit, whether it holds credentials
      static PROXIED: &[(&str, &str, bool)] = &[
      ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList proxiedRows instances))}
      ];

      const SSH: &str = "${pkgs.openssh}/bin/ssh";
      const SYSTEMCTL: &str = "${pkgs.systemd}/bin/systemctl";
      const JOURNALCTL: &str = "${pkgs.systemd}/bin/journalctl";
      const NFT: &str = "${pkgs.nftables}/bin/nft";
      const CP: &str = "${pkgs.coreutils}/bin/cp";
    ''
  )
