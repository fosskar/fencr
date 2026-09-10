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
    credentialExec
    parseAllow
    ;
in
{
  # one certificate authority per host, made on first use in a directory
  # root alone reads. each credential proxy signs its domain's certificate
  # with it, and a vm with a credential trusts it, fetched beside the secrets
  caUnit = "fencr-ca";
  caDir = "/var/lib/fencr/ca";
  caCert = "${caDir}/root.crt";
  caKey = "${caDir}/root.key";
  # the credential proxy loads the authority under these ids, beside the
  # credentials it is granted; a credential may not take them
  caMembers = {
    "ca.crt" = caCert;
    "ca.key" = caKey;
  };

  # what a vm with a credential fetches beside its secrets, and where the
  # guest installs it: the authority alone for node, the store bundle with
  # the authority appended for everything else
  guestTrust = {
    member = "fencr-ca.crt";
    cert = "/run/fencr/ca.crt";
    bundle = "/run/fencr/ca-bundle.crt";
  };
  trustVariables = {
    NIX_SSL_CERT_FILE = guestTrust.bundle;
    NODE_EXTRA_CA_CERTS = guestTrust.cert;
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

  # the apis a credential names by provider instead of by upstream and
  # header. the proxy works per host, so one row serves every path under it
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

  # an allow entry, "<methods> <path>": the methods caddy's matcher takes
  # (none for "*"), the path pattern (none for "*"), or the reason it is
  # malformed
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
  credentialSocketOf = cfg: "/run/${(unitsOf cfg.name).credentials}/credentials.sock";

  # the secrets reach caddy as FENCR_CREDENTIAL_<index>, since a credential
  # name is no environment variable name
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
      lib.imap0 (
        index: credential:
        let
          rules = map parseAllow (credential.allow or [ ]);
          indent =
            depth: lines: lib.concatMapStrings (line: "${lib.fixedWidthString depth " " ""}${line}\n") lines;
          proxy = [
            "reverse_proxy ${credential.upstream} {"
            "  header_up Host {upstream_hostport}"
            "  header_up ${credential.header} \"{$FENCR_CREDENTIAL_${toString index}}\""
            "}"
          ];
          # one named matcher per allow entry, a handle for each; the
          # bare handle answers what none admitted. a matcher's methods
          # and paths are each a disjunction, the two are conjoined
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
            # every request the credential rode on, method, path and status,
            # to the journal; headers are dropped from the record since the
            # guest's own header sits there
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
        exec ${pkgs.caddy}/bin/caddy run --config ${pkgs.writeText "fencr-credentials.caddyfile" (credentialCaddyfile socket credentials)} --adapter caddyfile
      ''
    );

  # the upstream is loopback or the internet; caddy resolves its name
  # through resolved's stub, since go reads resolv.conf itself
  credentialServiceConfig =
    pkgs: cfg:
    proxyHardening
    // {
      ExecStart = "${credentialExec pkgs (credentialSocketOf cfg) cfg.credentials}";
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
