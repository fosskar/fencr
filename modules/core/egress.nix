{ lib, core, ... }:
let
  inherit (core)
    caDir
    caCert
    caKey
    caMembers
    guestTrust
    hardened
    egressHardening
    upstreamHost
    domainPatternError
    unitsOf
    placeholderOf
    secretUnitOf
    secretSourceOf
    egressBin
    egressConfig
    egressDnsPort
    egressTlsPort
    parseAllow
    reloadUnit
    ;
  # the socket a credential's resolver listens on, which is what
  # LoadCredential reads instead of a file
  secretPathOf = name: "/run/fencr/secrets/${name}";
in
{
  # high ports the firewall redirects the guest's 53 and 443 to, so a host
  # service on *:443 or *:53 is no conflict and it binds unprivileged
  egressDnsPort = 33053;
  egressTlsPort = 33443;

  secretUnitOf = name: "fencr-secret-${name}";

  # LoadCredential takes a file or an AF_UNIX stream, so a credential with a
  # command reads the same way one with a file does and nothing downstream
  # knows the difference
  secretSourceOf =
    credential:
    if (credential.secretCommand or null) != null then
      secretPathOf credential.name
    else
      toString credential.secretFile;

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
  # restarts every vm's egress when any of their files is written.
  # rotation is rare and the restart momentary, which is why this is not a
  # pair of units per vm
  reloadUnit = "fencr-credentials-reload";

  egressBin = pkgs: pkgs.callPackage ../../pkgs/egress { };

  # one socket-activated resolver per dynamic credential. systemd connects
  # to the socket when a vm's egress unit starts and reads the value from
  # it, so the secret exists in that unit's credentials directory and
  # nowhere else: no file, no watcher, no copy of its own
  secretUnits =
    pkgs: credentials:
    let
      dynamic = lib.filterAttrs (_: credential: (credential.secretCommand or null) != null) credentials;
    in
    lib.optionalAttrs (dynamic != { }) {
      services = lib.mapAttrs' (
        name: credential:
        lib.nameValuePair "${secretUnitOf name}@" {
          description = "resolve the ${name} credential";
          unitConfig.CollectMode = "inactive-or-failed";
          # the command runs here and never in the proxy: the process that
          # ends the guest's tls must not be able to exec
          serviceConfig = hardened // {
            DynamicUser = true;
            StandardInput = "socket";
            StandardError = "journal";
            ExecStart = pkgs.writeShellScript "fencr-secret-${name}" ''
              set -euo pipefail
              value=$(${lib.escapeShellArgs credential.secretCommand})
              # a command that prints nothing has failed quietly, and an
              # empty header is worse than a unit that refuses to start
              [ -n "$value" ]
              printf '%s' "$value"
            '';
          };
        }
      ) dynamic;
      sockets = lib.mapAttrs' (
        name: _:
        lib.nameValuePair (secretUnitOf name) {
          description = "resolve the ${name} credential";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = secretPathOf name;
            SocketMode = "0600";
            Accept = true;
            MaxConnections = 4;
          };
        }
      ) dynamic;
    };

  reloadUnits =
    pkgs: instances:
    let
      granted = lib.filter (instance: instance.credentials != [ ]) (lib.attrValues instances);
      # only a file can be watched; a resolver's socket is read afresh every
      # time the unit that needs it starts
      files = lib.unique (
        lib.concatMap (
          instance:
          map secretSourceOf (
            lib.filter (credential: (credential.secretCommand or null) == null) instance.credentials
          )
        ) granted
      );
      proxies = map (instance: "${(unitsOf instance.name).egress}.service") granted;
    in
    lib.optionalAttrs (files != [ ]) {
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

  # the value the guest is given in place of the credential: not a secret,
  # so it may sit in the store, and derived from the vm and the credential
  # so it is stable across rebuilds and differs per vm
  placeholderOf =
    vm: name: "fencr-${builtins.substring 0 24 (builtins.hashString "sha256" "${vm}:${name}")}";

  credentialsOf =
    cfg: credentials:
    map (
      name:
      credentials.${name}
      // {
        inherit name;
        placeholder = placeholderOf cfg.name name;
        domain =
          if credentials.${name}.domain != null then
            credentials.${name}.domain
          else
            upstreamHost credentials.${name}.upstream;
      }
    ) (lib.filter (name: credentials ? ${name}) cfg.credentials);

  # one source or the other, never both and never neither: the fetch unit
  # owns the path a command writes, so a secretFile beside it would be
  # overwritten rather than read
  credentialSecretError =
    credential:
    if (credential.secretFile or null) != null && (credential.secretCommand or null) != null then
      "credential \"${credential.name}\": secretFile and secretCommand are alternatives, not a pair"
    else if (credential.secretFile or null) == null && (credential.secretCommand or null) == null then
      "credential \"${credential.name}\" needs fencr.credentials.${credential.name}.secretFile or .secretCommand"
    else
      null;

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

  # what the proxy is configured with: where it listens, the names a vm may
  # reach, and where each credential goes. no value is in here; the
  # credentials arrive as systemd credentials and are read per request
  egressConfig =
    cfg:
    builtins.toJSON {
      bridge = cfg.hostIp;
      dnsPort = egressDnsPort;
      tlsPort = egressTlsPort;
      # the stub resolved listens on for the host itself; with domain grants
      # there is a name to judge and no query leaves this unit
      resolver = if cfg.hostDns then "127.0.0.53:53" else "";
      inherit (cfg) domains denied;
      credentials = map (credential: {
        inherit (credential)
          name
          domain
          upstream
          header
          ;
        placeholder = credential.placeholder or "";
        allow = map (rule: {
          inherit (rule) methods;
          path = if rule.path == null then "" else rule.path;
        }) (map parseAllow (credential.allow or [ ]));
      }) cfg.credentials;
    };

  # one process for the vm's road out and its credentials: it listens on
  # the bridge, so it needs no socket of its own and no group to share one
  egressServiceConfig =
    pkgs: cfg:
    egressHardening
    // {
      ExecStart = "${egressBin pkgs}/bin/fencr-egress ${pkgs.writeText "fencr-egress.json" (egressConfig cfg)}";
      LoadCredential =
        map (credential: "${credential.name}:${secretSourceOf credential}") cfg.credentials
        ++ lib.optionals (cfg.credentials != [ ]) (
          lib.mapAttrsToList (member: path: "${member}:${path}") caMembers
        );
      # checked before egressHardening's deny list, so it names only what that
      # would otherwise take: the guest's own subnet, a loopback upstream and
      # resolved's stub. the internet needs no entry
      IPAddressAllow = [
        "127.0.0.1/32"
        "127.0.0.53/32"
        cfg.subnet
      ];
    };
}
