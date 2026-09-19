# the instance table is baked in at eval, so the binary needs no manifest
# and no daemon; the program is cli.go
{
  lib,
  pkgs,
  instances,
}:
let
  core = import ../../modules/core { inherit lib; };
  # a grant's text and where its use shows
  grant =
    text: kind: value:
    "{Text: ${builtins.toJSON text}, Source: Source{${kind}, ${builtins.toJSON value}}},";
  counted = text: tag: grant text "\"counter\"" tag;
  ports = lib.concatMapStringsSep ", " toString;
  inbound =
    cfg:
    let
      opened = core.guestPortsOf cfg;
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
    ++ map (domain: grant "${domain} TLS 443" "\"domain\"" domain) cfg.domains
    ++ map (domain: grant "!${domain} TLS 443 (denied)" "\"denied\"" domain) cfg.denied
    ++ map (
      credential:
      grant "${credential.domain} TLS 443 (credential ${credential.name})" "\"credential\""
        credential.domain
    ) cfg.credentials;
  sandboxRow =
    name: cfg:
    ''{Name: "${name}", ID: ${toString cfg.id}, IP: "${cfg.ip}", HostIP: "${cfg.hostIp}", Inbound: []Grant{${lib.concatStrings (inbound cfg)}}, Outbound: []Grant{${lib.concatStrings (outbound cfg)}}, Unit: "${(core.unitsOf name).microvm}.service", CheckpointUnit: "${(core.unitsOf name).checkpoint}@", EgressUnit: "${lib.optionalString cfg.egress "${(core.unitsOf name).egress}.service"}", Credentials: ${
      if cfg.credentials != [ ] then "true" else "false"
    }, StateDir: "${core.stateDirOf name}", CheckpointDir: "${core.checkpointDirOf name}", Image: "${core.stateImageOf name}", APISocket: "${core.apiSocketOf name}", JumpUser: "${core.jumpUserOf name}", SSH: ${
      if cfg.sshKeys != [ ] then "true" else "false"
    }},'';

  tables = pkgs.writeText "tables.go" ''
    package main

    var sandboxes = []Sandbox{
    ${lib.concatStrings (lib.mapAttrsToList sandboxRow instances)}
    }

    const (
    	sshBin        = "${pkgs.openssh}/bin/ssh"
    	systemctlBin  = "${pkgs.systemd}/bin/systemctl"
    	journalctlBin = "${pkgs.systemd}/bin/journalctl"
    	nftBin        = "${pkgs.nftables}/bin/nft"
    	cpBin         = "${pkgs.coreutils}/bin/cp"
    	statBin       = "${pkgs.coreutils}/bin/stat"
    	lsattrBin     = "${pkgs.e2fsprogs}/bin/lsattr"
    	chattrBin     = "${pkgs.e2fsprogs}/bin/chattr"
    	curlBin       = "${pkgs.curl}/bin/curl"
    )
  '';

  # domain.go is shared with the egress unit, so the wildcard rule has one
  # definition rather than a twin per language
  src = pkgs.runCommand "fencr-cli-src" { } ''
    mkdir -p "$out"
    cp ${./go.mod} "$out/go.mod"
    cp ${./cli.go} "$out/cli.go"
    cp ${../domain.go} "$out/domain.go"
    cp ${tables} "$out/tables.go"
  '';
in
pkgs.buildGoModule {
  pname = "fencr";
  version = "0";
  inherit src;
  vendorHash = null;
  env.CGO_ENABLED = 0;
  meta.mainProgram = "fencr";
}
