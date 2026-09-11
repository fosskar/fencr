{ lib, core, ... }:
let
  inherit (core)
    caDir
    caCert
    caKey
    caMembers
    guestTrust
    hardened
    proxyHardening
    upstreamHost
    domainPatternError
    unitsOf
    credentialSocketOf
    credentialCaddyfile
    parseAllow
    reloadUnit
    ;
in
{
  caUnit = "fencr-ca";
  caDir = "/var/lib/fencr/ca";
  caCert = "${caDir}/root.crt";
  caKey = "${caDir}/root.key";
  # credential ids the authority takes in the proxy unit; a credential may not use them
  caMembers = {
    "ca.crt" = caCert;
    "ca.key" = caKey;
  };

  # node takes the authority alone, everything else the store bundle with it appended
  guestTrust = {
    member = "fencr-ca.crt";
    cert = "/run/fencr/ca.crt";
    bundle = "/run/fencr/ca-bundle.crt";
  };
  trustVariables = {
    NIX_SSL_CERT_FILE = guestTrust.bundle;
    NODE_EXTRA_CA_CERTS = guestTrust.cert;
  };

  # LoadCredential copies a secretFile once, at start, and a path unit can
  # only start a unit, never restart one; so one watcher for the host
  # restarts every credential proxy when any of their files is written.
  # rotation is rare and the restart momentary, which is why this is not a
  # pair of units per vm
  reloadUnit = "fencr-credentials-reload";

  reloadUnits =
    pkgs: instances:
    let
      granted = lib.filter (instance: instance.credentials != [ ]) (lib.attrValues instances);
      files = lib.unique (
        lib.concatMap (
          instance: map (credential: toString credential.secretFile) instance.credentials
        ) granted
      );
      proxies = map (instance: "${(unitsOf instance.name).credentials}.service") granted;
    in
    lib.optionalAttrs (granted != [ ]) {
      services.${reloadUnit} = {
        description = "reload the credential proxies";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.systemd}/bin/systemctl try-restart ${lib.concatStringsSep " " proxies}";
        };
      };
      paths.${reloadUnit} = {
        description = "watch the credential files";
        wantedBy = [ "multi-user.target" ];
        pathConfig = {
          PathChanged = files;
          PathModified = files;
        };
      };
    };

  caService = pkgs: hostName: {
    description = "fencr certificate authority";
    unitConfig.ConditionPathExists = "!${caKey}";
    serviceConfig = hardened // {
      Type = "oneshot";
      StateDirectory = "fencr/ca";
      StateDirectoryMode = "0700";
    };
    script = ''
      ${pkgs.openssl}/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=fencr on ${hostName}" -days 7300 -keyout ${caKey} -out ${caCert}
    '';
  };

  providers = {
    anthropic = {
      upstream = "https://api.anthropic.com";
      header = "x-api-key";
    };
    openai = {
      upstream = "https://api.openai.com";
      header = "Authorization";
    };
    openrouter = {
      upstream = "https://openrouter.ai";
      header = "Authorization";
    };
    opencode = {
      upstream = "https://opencode.ai";
      header = "Authorization";
    };
  };

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

  # "<methods> <path>"; "*" on either side means no matcher
  parseAllow =
    entry:
    let
      words = lib.filter (word: word != "") (lib.splitString " " entry);
      methods = lib.head words;
      path = lib.last words;
    in
    if lib.length words != 2 then
      {
        error = "\"${entry}\": expected \"<methods> <path>\"";
      }
    else if methods != "*" && builtins.match "[A-Z]+(,[A-Z]+)*" methods == null then
      {
        error = "\"${entry}\": methods are upper-case names separated by commas, or \"*\"";
      }
    else if path != "*" && !lib.hasPrefix "/" path then
      {
        error = "\"${entry}\": the path starts with \"/\", or is \"*\"";
      }
    else
      {
        methods = lib.optionals (methods != "*") (lib.splitString "," methods);
        path = if path == "*" then null else path;
        error = null;
      };

  credentialAllowErrors =
    credential:
    map (rule: "credential \"${credential.name}\": allow entry ${rule.error}") (
      lib.filter (rule: rule.error != null) (map parseAllow (credential.allow or [ ]))
    );

  # a unix socket in group kvm, not a loopback port: only the vm's egress proxy
  # reaches it, no other host process can borrow a credential through it
  credentialSocketOf = cfg: "/run/${(unitsOf cfg.name).credentials}/credentials.sock";

  # {file.} is read per request and strips the trailing newline; {$CREDENTIALS_DIRECTORY}
  # is expanded at parse time, so no secret crosses the environment
  credentialCaddyfile =
    socket: credentials:
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
      map (
        credential:
        let
          rules = map parseAllow (credential.allow or [ ]);
          indent =
            depth: lines: lib.concatMapStrings (line: "${lib.fixedWidthString depth " " ""}${line}\n") lines;
          proxy = [
            "reverse_proxy ${credential.upstream} {"
            "  header_up Host {upstream_hostport}"
            "  header_up ${credential.header} \"{file.{$CREDENTIALS_DIRECTORY}/${credential.name}}\""
            "}"
          ];
          # a caddy matcher ORs its methods and ORs its paths, ANDs the two
          matcher =
            i: rule:
            indent 2 (
              [ "@allow${toString i} {" ]
              ++ lib.optional (rule.methods != [ ]) "  method ${lib.concatStringsSep " " rule.methods}"
              ++ lib.optional (rule.path != null) "  path ${rule.path}"
              ++ [
                "}"
                "handle @allow${toString i} {"
              ]
            )
            + indent 4 proxy
            + indent 2 [ "}" ];
        in
        ''
          https://${credential.domain} {
            bind unix/${socket}|0660
            tls internal
            # headers dropped from the record: the guest's own header sits there
            log {
              output stderr
              format filter {
                wrap json
                fields {
                  request>headers delete
                  resp_headers delete
                }
              }
            }
        ''
        + (
          if rules == [ ] then
            indent 2 proxy
          else
            lib.concatStrings (lib.imap0 matcher rules)
            + indent 2 [
              "handle {"
              "  respond \"fencr: request not allowed for credential ${credential.name}\" 403"
              "}"
            ]
        )
        + "}\n"
      ) credentials
    );

  # go reads resolv.conf itself, so resolved's stub is allowed
  credentialServiceConfig =
    pkgs: cfg:
    proxyHardening
    // {
      ExecStart = "${pkgs.caddy}/bin/caddy run --config ${pkgs.writeText "fencr-credentials.caddyfile" (credentialCaddyfile (credentialSocketOf cfg) cfg.credentials)} --adapter caddyfile";
      LoadCredential =
        map (credential: "${credential.name}:${credential.secretFile}") cfg.credentials
        ++ lib.mapAttrsToList (member: path: "${member}:${path}") caMembers;
      Environment = [
        "XDG_DATA_HOME=/tmp"
        "XDG_CONFIG_HOME=/tmp"
      ];
      RuntimeDirectory = (unitsOf cfg.name).credentials;
      RuntimeDirectoryMode = "0750";
      IPAddressAllow = [
        "127.0.0.1/32"
        "127.0.0.53/32"
      ];
    };
}
