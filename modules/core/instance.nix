{ lib, core, ... }:
let
  inherit (core)
    defaults
    tapOf
    bridgeOf
    macOf
    memoryMaxOf
    cidOf
    hostIpOf
    ipOf
    idRange
    prefixLength
    subnetOf
    stateDirOf
    runDirOf
    parseOutbound
    credentialsOf
    credentialDomainError
    credentialSecretError
    credentialAllowErrors
    credentialId
    caMembers
    guestTrust
    domainPatternError
    domainCovers
    duplicates
    guestFields
    ;
in
{
  # resolveInstance applies these too, so a check that omits an option gets
  # the vm the module would build
  defaults = {
    vcpu = 4;
    mem = 4096;
    cpuQuota = "400%";
    memoryMax = null;
    stateSize = 32768;
    diskBandwidth = null;
    networkBandwidth = null;
    maxConnections = 2048;
    checkpoints = {
      onStop = true;
      interval = null;
      keep = 5;
    };
    credentials = [ ];
    inbound = [ ];
    outbound = [ ];
    secrets = { };
  };

  # the guest's memory plus room for firecracker
  memoryMaxOf = mem: "${toString (mem + 512)}M";

  tapOf = name: "tap-${name}";
  bridgeOf = name: "br-${name}";
  # a new name that sorts earlier moves every id after it; `id` pins one
  idRange = 256;
  idOf =
    names: name: lib.lists.findFirstIndex (other: other == name) null (lib.sort lib.lessThan names);
  macOf = cfg: "02:00:00:00:20:${lib.toLower (lib.fixedWidthString 2 "0" (lib.toHexString cfg.id))}";
  cidOf = cfg: 3 + cfg.id;
  hostIpOf = cfg: "10.11.${toString cfg.id}.1";
  ipOf = cfg: "10.11.${toString cfg.id}.2";
  prefixLength = 26;
  subnetOf = cfg: "10.11.${toString cfg.id}.0/${toString prefixLength}";

  stateDirOf = name: "/var/lib/fencr-vms/${name}";
  stateImageOf = name: "${stateDirOf name}/state.img";
  userOf = name: "fencr-${name}";
  unitsOf = name: {
    vm = "fencr-${name}";
    egress = "fencr-${name}-egress";
    secrets = "fencr-${name}-secrets";
    checkpoint = "fencr-${name}-checkpoint";
  };
  # firecracker's vsock: one socket in, "<vsock>_<port>" out, in a directory
  # only the vm's user enters, which is what makes the path the identity
  runDirOf = name: "/run/fencr-${name}";
  vsockOf = name: "${runDirOf name}/vsock";
  powerPort = 4;
  secretsPort = 5;

  # addresses are rejected before domain validation: domainPatternError would
  # accept a dotted quad, and an address without a port must be an error
  parseOutbound =
    entry:
    let
      valid = kind: value: {
        inherit kind value;
        text = entry;
        error = null;
      };
      invalid = error: {
        kind = "invalid";
        value = null;
        inherit error;
        text = entry;
      };
      # "010" is refused rather than read as ten by one reader and eight by another
      number =
        text: maximum: builtins.match "0|[1-9][0-9]{0,9}" text != null && lib.toIntBase10 text <= maximum;
      parts = lib.splitString ":" entry;
      address = builtins.head parts;
      port = lib.last parts;
      network = lib.splitString "/" address;
      octets = lib.splitString "." (builtins.head network);
      portError =
        if port == "" then
          "missing port"
        else if !number port 65535 || port == "0" then
          "port must be between 1 and 65535, written without leading zeros"
        else
          null;
    in
    if entry == "internet" then
      valid "internet" entry
    else if lib.hasPrefix "!" entry then
      let
        pattern = lib.removePrefix "!" entry;
      in
      if domainPatternError pattern != null then
        invalid "a deny entry names a domain pattern; ${domainPatternError pattern}"
      else
        valid "deny" pattern
    else if entry == "host" then
      invalid "host needs a port; expected host:<port>"
    else if lib.length parts > 2 then
      invalid "expected one colon separating the destination and port"
    else if lib.hasPrefix "host:" entry then
      if portError == null then valid "host" (lib.toIntBase10 port) else invalid portError
    else if builtins.match "[0-9./]+:.*" entry != null then
      if lib.length octets != 4 || !lib.all (octet: builtins.match "[0-9]+" octet != null) octets then
        invalid "expected a dotted-quad IPv4 address"
      else if !lib.all (octet: number octet 255) octets then
        invalid "octet out of range or written with a leading zero"
      else if lib.length network > 2 || (lib.length network == 2 && !number (lib.last network) 32) then
        invalid "prefix must be between 0 and 32, written without leading zeros"
      else if portError != null then
        invalid portError
      else
        valid "tcp" {
          inherit address;
          port = lib.toIntBase10 port;
        }
    else if
      builtins.match "[0-9./]+" entry != null
      || builtins.match "[0-9]+" (lib.last (lib.splitString "." entry)) != null
    then
      invalid "an address needs a port"
    else if lib.hasInfix ":" entry then
      invalid "expected host:<port> or <ipv4[/prefix]>:<port>; domains use TLS on 443 without a port"
    else if domainPatternError entry != null then
      invalid (domainPatternError entry)
    else
      valid "domain" entry;

  duplicates =
    values: lib.unique (lib.filter (value: lib.count (other: other == value) values > 1) values);

  # the eval-time twin of covers() in pkgs/domain.rs
  domainCovers =
    pattern: host:
    if lib.hasPrefix "*." pattern then
      lib.hasSuffix (lib.removePrefix "*" pattern) host
    else
      pattern == host;

  # secrets and credentials become systemd credential ids
  credentialId = value: builtins.match "[A-Za-z0-9_.-]+" value != null;

  # "*github.com" would also match evilgithub.com, and stray metacharacters
  # widen an allowlist silently
  domainPatternError =
    pattern:
    if builtins.match "(\\*\\.)?([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+" pattern != null then
      null
    else if lib.hasPrefix "*" pattern && !lib.hasPrefix "*." pattern then
      "\"${pattern}\": a wildcard must be its own label (\"*.example.com\"); \"*example.com\" also matches evilexample.com"
    else
      "\"${pattern}\": not a hostname pattern; expected \"example.com\" or \"*.example.com\"";

  # the one list the guest's firewall and the host's output chain both take
  guestPortsOf = cfg: lib.optional (cfg.sshKeys != [ ]) 22 ++ cfg.inbound;

  # agentSandbox: the machine's shape and network posture, no host path
  guestFields = [
    "bridge"
    "cid"
    "credentialDomains"
    "credentialEnv"
    "credentialPlaceholders"
    "diskBandwidth"
    "dns"
    "hostIp"
    "inbound"
    "ip"
    "mac"
    "mem"
    "name"
    "networkBandwidth"
    "secretNames"
    "sshKeys"
    "stateSize"
    "tap"
    "vcpu"
  ];
  guestOf = instance: lib.getAttrs guestFields instance;

  resolveInstance =
    {
      name,
      sshKeys ? [ ],
      credentials ? { },
      ...
    }@args:
    let
      options = defaults // args.options;
      entries = map parseOutbound options.outbound;
      values = kind: map (entry: entry.value) (lib.filter (entry: entry.kind == kind) entries);
      internet = values "internet" != [ ];
      domains = values "domain";
      denied = values "deny";
      granted = credentialsOf (options // { inherit name; }) credentials;
      tap = tapOf name;
      secretNames = lib.attrNames options.secrets;
      # the guest's resolver is always the vm's egress unit, which answers
      # every name with the bridge address where there is a name to judge
      # and relays to the host's stub where there is not. the guest never
      # speaks to resolved itself
      egress = domains != [ ] || granted != [ ] || internet;
      dnsEgress = domains != [ ] || internet;
      hostDns = internet;
      errors =
        lib.optional (
          options.id < 0 || options.id >= idRange
        ) "${name}: id must be between 0 and ${toString (idRange - 1)}"
        ++ map (
          secretName:
          "${name}: secret name \"${secretName}\" contains characters unsupported by systemd credentials"
        ) (lib.filter (secretName: !credentialId secretName) secretNames)
        ++ lib.optional (lib.elem guestTrust.member secretNames) "${name}: secret name \"${guestTrust.member}\" is reserved for the authority"
        ++ lib.optional (
          lib.stringLength tap > 15
        ) "vm name \"${name}\" is too long: \"${tap}\" exceeds IFNAMSIZ"
        ++ lib.optional (
          domains != [ ] && internet
        ) "${name}: outbound cannot combine internet with domain grants"
        ++ map (entry: "${name}: outbound entry \"${entry.text}\": ${entry.error}") (
          lib.filter (entry: entry.error != null) entries
        )
        # a deny that covers nothing is a typo; one equal to a grant empties it
        ++ map (pattern: "${name}: outbound entry \"!${pattern}\" denies the whole grant \"${pattern}\"") (
          lib.filter (pattern: lib.elem pattern domains) denied
        )
        ++
          map
            (
              pattern: "${name}: outbound entry \"!${pattern}\" denies nothing: no domain grant covers ${pattern}"
            )
            (
              lib.filter (
                pattern:
                !lib.elem pattern domains
                && !lib.any (allowed: domainCovers allowed (lib.removePrefix "*." pattern)) domains
              ) denied
            )
        ++ map (credential: "${name}: credential \"${credential}\" is not declared in fencr.credentials") (
          lib.filter (credential: !(credentials ? ${credential})) options.credentials
        )
        ++ map (
          credential:
          "${name}: credential name \"${credential.name}\" contains characters unsupported by systemd credentials"
        ) (lib.filter (credential: !credentialId credential.name) granted)
        ++ map (
          credential: "${name}: credential name \"${credential.name}\" is reserved for the authority"
        ) (lib.filter (credential: caMembers ? ${credential.name}) granted)
        ++ map (error: "${name}: ${error}") (
          lib.filter (error: error != null) (
            map credentialDomainError granted ++ map credentialSecretError granted
          )
          ++ lib.concatMap credentialAllowErrors granted
        )
        ++ map (domain: "${name}: credential domain ${domain} granted twice") (
          duplicates (map (credential: credential.domain) granted)
        )
        ++ map (port: "${name}: inbound port ${toString port} declared twice") (duplicates options.inbound);
    in
    {
      inherit
        name
        sshKeys
        errors
        tap
        secretNames
        internet
        domains
        denied
        egress
        dnsEgress
        hostDns
        ;
      inherit (options)
        id
        vcpu
        mem
        stateSize
        cpuQuota
        diskBandwidth
        networkBandwidth
        maxConnections
        checkpoints
        inbound
        secrets
        ;
      hostPorts = values "host";
      destinations = values "tcp";
      memoryMax = if options.memoryMax != null then options.memoryMax else memoryMaxOf options.mem;
      credentials = granted;
      credentialDomains = map (credential: credential.domain) granted;
      # what the guest may send in place of a credential; the proxy puts the
      # real value where this appears
      credentialEnv = lib.listToAttrs (
        map (credential: lib.nameValuePair credential.guestEnv credential.placeholder) (
          lib.filter (credential: credential.guestEnv or null != null) granted
        )
      );
      credentialPlaceholders = lib.listToAttrs (
        map (credential: lib.nameValuePair credential.name credential.placeholder) granted
      );
      dns = if dnsEgress || hostDns then hostIpOf options else null;
      bridge = bridgeOf name;
      mac = macOf options;
      cid = cidOf options;
      hostIp = hostIpOf options;
      ip = ipOf options;
      subnet = subnetOf options;
    };

  hostErrors =
    instances:
    map (
      id:
      "instance id ${toString id} is shared by ${
        lib.concatStringsSep ", " (
          lib.attrNames (lib.filterAttrs (_: instance: instance.id == id) instances)
        )
      }; set id on one of them"
    ) (duplicates (map (instance: instance.id) (lib.attrValues instances)));
}
