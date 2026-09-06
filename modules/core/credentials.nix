{ lib, core, ... }:
let
  inherit (core)
    caDir
    caCert
    caKey
    proxyHardening
    specialUseNetworks
    upstreamHost
    domainPatternError
    credentialRuntimeDirOf
    credentialSocketOf
    credentialCaddyfile
    credentialExec
    ;
in
{
  # one certificate authority per host, made on first use in a directory
  # root alone reads. each credential proxy signs its domain's certificate
  # with it, and a vm with a credential trusts it, fetched beside the secrets
  caUnit = "fencr-ca.service";
  caDir = "/var/lib/fencr/ca";
  caCert = "${caDir}/root.crt";
  caKey = "${caDir}/root.key";

  trustVariables = {
    NIX_SSL_CERT_FILE = "/run/fencr/ca-bundle.crt";
    NODE_EXTRA_CA_CERTS = "/run/fencr/ca.crt";
  };

  caService = pkgs: hostName: {
    description = "fencr certificate authority";
    unitConfig.ConditionPathExists = "!${caKey}";
    serviceConfig = {
      Type = "oneshot";
      StateDirectory = "fencr/ca";
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
    script = ''
      ${pkgs.openssl}/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=fencr on ${hostName}" -days 7300 -keyout ${caKey} -out ${caCert}
    '';
  };

  # a credential's domain is the name the vm calls; it defaults to the
  # upstream's host, which a loopback upstream cannot supply
  upstreamHost =
    upstream:
    let
      host = builtins.match "https?://([^/:]+).*" upstream;
    in
    if host == null then null else builtins.head host;

  credentialsOf =
    cfg: credentials:
    map (
      name:
      credentials.${name}
      // {
        inherit name;
        domain =
          if credentials.${name}.domain != null then
            credentials.${name}.domain
          else
            upstreamHost credentials.${name}.upstream;
      }
    ) (lib.filter (name: credentials ? ${name}) cfg.credentials);

  credentialDomainError =
    credential:
    if
      credential.domain == null
      || credential.domain == "localhost"
      || builtins.match "[0-9.]+" credential.domain != null
    then
      "credential \"${credential.name}\" needs fencr.credentials.${credential.name}.domain: its upstream \"${credential.upstream}\" names no host a vm could call"
    else if lib.hasPrefix "*" credential.domain || domainPatternError credential.domain != null then
      "credential \"${credential.name}\": domain \"${credential.domain}\" is not a host name"
    else
      null;

  # the vm's credential proxy: the guest calls a credential's domain as
  # usual and lands here, where one caddy per vm holds a certificate for
  # each granted domain from the host's authority, ends the tls, injects
  # that credential's header and sends the request on, originating tls to
  # an https upstream itself. the secrets never exist inside the vm; the
  # vm can use every credential granted to it anyway, so one process for
  # all of them separates nothing the vm could not reach. it listens on a
  # unix socket in its own runtime directory, group kvm, so only the vm's
  # egress proxy reaches it: no host loopback port, nothing for another
  # host process to borrow a credential through
  credentialRuntimeDirOf = cfg: "fencr-credentials-${cfg.name}";

  credentialSocketOf = cfg: "/run/${credentialRuntimeDirOf cfg}/credentials.sock";

  # the secrets reach caddy as FENCR_CREDENTIAL_<index>, since a credential
  # name is no environment variable name
  credentialCaddyfile =
    pkgs: socket: credentials:
    pkgs.writeText "fencr-credentials.caddyfile" (
      ''
        {
          admin off
          auto_https disable_redirects
          pki {
            ca local {
              root {
                cert {$CREDENTIALS_DIRECTORY}/ca.crt
                key {$CREDENTIALS_DIRECTORY}/ca.key
              }
            }
          }
        }
      ''
      + lib.concatStrings (
        lib.imap0 (index: credential: ''
          https://${credential.domain} {
            bind unix/${socket}|0660
            tls internal
            reverse_proxy ${credential.upstream} {
              header_up Host {upstream_hostport}
              header_up ${credential.header} "{$FENCR_CREDENTIAL_${toString index}}"
            }
          }
        '') credentials
      )
    );

  credentialExec =
    pkgs: socket: credentials:
    pkgs.writeShellScript "fencr-credentials" (
      lib.concatStrings (
        lib.imap0 (index: credential: ''
          FENCR_CREDENTIAL_${toString index}="$(cat "$CREDENTIALS_DIRECTORY/${credential.name}")"
          export FENCR_CREDENTIAL_${toString index}
        '') credentials
      )
      + ''
        exec ${pkgs.caddy}/bin/caddy run --config ${
          credentialCaddyfile pkgs socket credentials
        } --adapter caddyfile
      ''
    );

  # the upstream is loopback or the internet; a private range is never a
  # credential target, so an allowed name cannot resolve into the lan
  credentialServiceConfig =
    pkgs: cfg:
    proxyHardening
    // {
      ExecStart = "${credentialExec pkgs (credentialSocketOf cfg) cfg.credentials}";
      LoadCredential =
        map (credential: "${credential.name}:${credential.secretFile}") cfg.credentials
        ++ [
          "ca.crt:${caCert}"
          "ca.key:${caKey}"
        ];
      Environment = [
        "XDG_DATA_HOME=/tmp"
        "XDG_CONFIG_HOME=/tmp"
      ];
      Group = "kvm";
      RuntimeDirectory = credentialRuntimeDirOf cfg;
      RuntimeDirectoryMode = "0750";
      IPAddressAllow = [
        "0.0.0.0/0"
        "::/0"
        "127.0.0.1/32"
      ];
      IPAddressDeny = specialUseNetworks.v4 ++ specialUseNetworks.v6;
      RestrictAddressFamilies = [
        "AF_INET"
        "AF_INET6"
        "AF_UNIX"
      ];
    };
}
