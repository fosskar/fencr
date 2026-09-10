# the fencr command: read-only convenience over the declared instances.
# mutation stays with nixos-rebuild. the instance table is baked at eval,
# so the binary needs no manifest and no daemon. the program is cli.rs;
# this file appends the tables and tool paths it reads
{
  lib,
  pkgs,
  instances,
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

  # the proxy and credential units a vm runs, for the journals the
  # command reads
  proxiedRows =
    name: cfg: lib.optional cfg.proxy ''("${name}", "${(core.unitsOf name).proxy}.service"),'';

  credentialRows =
    name: cfg:
    lib.optional (
      cfg.credentials != [ ]
    ) ''("${name}", "${(core.unitsOf name).credentials}.service"),'';
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

      // vm, egress proxy unit
      static PROXIED: &[(&str, &str)] = &[
      ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList proxiedRows instances))}
      ];

      // vm, credential unit
      static CREDENTIALS: &[(&str, &str)] = &[
      ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList credentialRows instances))}
      ];

      const SSH: &str = "${pkgs.openssh}/bin/ssh";
      const SYSTEMCTL: &str = "${pkgs.systemd}/bin/systemctl";
      const JOURNALCTL: &str = "${pkgs.systemd}/bin/journalctl";
      const NFT: &str = "${pkgs.nftables}/bin/nft";
      const CP: &str = "${pkgs.coreutils}/bin/cp";
    ''
  )
