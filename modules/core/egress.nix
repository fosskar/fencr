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
    egressBin
    egressConfig
    egressDnsPort
    egressTlsPort
    parseAllow
    reloadUnit
    ;
in
{
  # high ports the firewall redirects the guest's 53 and 443 to, so a host
  # service on *:443 or *:53 is no conflict and it binds unprivileged
  egressDnsPort = 33053;
  egressTlsPort = 33443;

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

  reloadUnits =
    pkgs: instances:
    let
      granted = lib.filter (instance: instance.credentials != [ ]) (lib.attrValues instances);
      files = lib.unique (
        lib.concatMap (
          instance: map (credential: toString credential.secretFile) instance.credentials
        ) granted
      );
      proxies = map (instance: "${(unitsOf instance.name).egress}.service") granted;
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
        map (credential: "${credential.name}:${credential.secretFile}") cfg.credentials
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
