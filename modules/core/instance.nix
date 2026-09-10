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
    dnsProxyOf
    hostDnsOf
    proxyOf
    credentialsOf
    credentialDomainError
    credentialAllowErrors
    credentialId
    caMembers
    guestTrust
    domainPatternError
    domainCovers
    duplicates
    ;
in
{
  # applied again in resolveInstance, so a check that omits an option still
  # gets the same vm the module would build
  defaults = {
    vcpu = 4;
    mem = 4096;
    cpuQuota = "400%";
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

  # the unit's hard cap: the guest's memory plus room for firecracker
  memoryMaxOf = mem: "${toString (mem + 512)}M";

  tapOf = name: "tap-${name}";
  bridgeOf = name: "br-${name}";
  # a vm's default id is its position among the host's vm names, so a new
  # name that sorts earlier moves the ones after it; `id` pins one in place
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
  # the vm's units, keyed as systemd.services and systemd.sockets take them
  unitsOf = name: {
    vm = "fencr-${name}";
    proxy = "fencr-${name}-egress-proxy";
    credentials = "fencr-${name}-credentials";
    secrets = "fencr-${name}-secrets";
    checkpoint = "fencr-${name}-checkpoint";
  };
  # firecracker's vsock on the host: one unix socket for connections into
  # the guest, and one per port, "<vsock>_<port>", for connections out of
  # it, in a directory only the vm's user enters
  runDirOf = name: "/run/fencr-${name}";
  vsockOf = name: "${runDirOf name}/vsock";
  # the power button: a guest listener on this vsock port reboots on any
  # connection, and only the vm's user can open the vsock
  powerPort = 4;
  # raw secrets: at boot the guest fetches them as one archive from a host
  # socket only the vm's own user can open; the host side reads them as
  # systemd credentials, so they touch neither the store nor a disk
  secretsPort = 5;

  # domainPatternError also accepts dotted IPv4 addresses and numeric final
  # labels; reject these before domain validation so addresses require a port.
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
      decimal =
        text: maximum:
        let
          matched = builtins.match "0*([1-9][0-9]*|0)" text;
          digits = builtins.head matched;
        in
        matched != null
        && lib.stringLength digits <= lib.stringLength (toString maximum)
        && lib.toIntBase10 digits <= maximum;
      parts = lib.splitString ":" entry;
      address = builtins.head parts;
      port = lib.last parts;
      network = lib.splitString "/" address;
      octets = lib.splitString "." (builtins.head network);
      portError =
        if port == "" then
          "missing port"
        else if builtins.match "[0-9]+" port == null then
          "port must be a decimal integer"
        else if !decimal port 65535 || lib.toIntBase10 port < 1 then
          "port must be between 1 and 65535"
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
      else if !lib.all (octet: decimal octet 255) octets then
        invalid "octet out of range"
      else if lib.length network > 2 || (lib.length network == 2 && !decimal (lib.last network) 32) then
        invalid "prefix must be between 0 and 32"
      else if portError != null then
        invalid portError
      else
        valid "tcp" {
          address =
            lib.concatMapStringsSep "." (octet: toString (lib.toIntBase10 octet)) octets
            + lib.optionalString (lib.length network == 2) "/${toString (lib.toIntBase10 (lib.last network))}";
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

  # "*.example.com" covers the names below example.com, not example.com;
  # a deny pattern is covered when the name its wildcard stands under is
  domainCovers =
    pattern: host:
    if lib.hasPrefix "*." pattern then
      lib.hasSuffix (lib.removePrefix "*" pattern) host
    else
      pattern == host;

  # secrets and credentials become systemd credential ids on the host
  credentialId = value: builtins.match "[A-Za-z0-9_.-]+" value != null;

  # a pattern is a hostname, optionally with a leading "*." label. anything
  # else is rejected: "*github.com" also matches evilgithub.com, and stray
  # fnmatch metacharacters widen the allowlist silently.
  domainPatternError =
    pattern:
    if builtins.match "(\\*\\.)?([a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+" pattern != null then
      null
    else if lib.hasPrefix "*" pattern && !lib.hasPrefix "*." pattern then
      "\"${pattern}\": a wildcard must be its own label (\"*.example.com\"); \"*example.com\" also matches evilexample.com"
    else
      "\"${pattern}\": not a hostname pattern; expected \"example.com\" or \"*.example.com\"";

  # the guest ports the host may reach at the guest's address: its sshd
  # when keys authorize one, and what expose lists. the guest's firewall
  # opens exactly these and the host's output chain admits exactly these
  guestPortsOf = cfg: lib.optional (cfg.sshKeys != [ ]) 22 ++ cfg.expose;

  resolveInstance =
    {
      name,
      sshKeys ? [ ],
      credentials ? { },
      ...
    }@args:
    let
      declared = defaults // args.options;
      entries = map parseOutbound declared.outbound;
      values = kind: map (entry: entry.value) (lib.filter (entry: entry.kind == kind) entries);
      options = declared // {
        egress = if values "internet" != [ ] then "open" else "closed";
        allowedDomains = values "domain";
        deniedDomains = values "deny";
        allowedTCPDestinations = values "tcp";
        hostPorts = values "host";
      };
      granted = credentialsOf options credentials;
      guest = {
        inherit name sshKeys;
        inherit (options)
          vcpu
          mem
          stateSize
          diskBandwidth
          networkBandwidth
          ;
        # the host is the guest's resolver: the egress proxy with a domain
        # allowlist, resolved with open egress; closed egress reaches none
        dns = if dnsProxyOf options || hostDnsOf options then hostIpOf options else null;
        tap = tapOf name;
        bridge = bridgeOf name;
        mac = macOf options;
        cid = cidOf options;
        hostIp = hostIpOf options;
        ip = ipOf options;
        expose = options.inbound;
        credentialDomains = map (credential: credential.domain) granted;
        secretNames = lib.attrNames options.secrets;
      };
      errors =
        lib.optional (
          options.id < 0 || options.id >= idRange
        ) "${name}: id must be between 0 and ${toString (idRange - 1)}"
        ++ map (
          secretName:
          "${name}: secret name \"${secretName}\" contains characters unsupported by systemd credentials"
        ) (lib.filter (secretName: !credentialId secretName) guest.secretNames)
        ++ lib.optional (lib.elem guestTrust.member guest.secretNames) "${name}: secret name \"${guestTrust.member}\" is reserved for the authority"
        ++ lib.optional (
          lib.stringLength guest.tap > 15
        ) "vm name \"${name}\" is too long: \"${guest.tap}\" exceeds IFNAMSIZ"
        ++ lib.optional (
          options.allowedDomains != [ ] && options.egress != "closed"
        ) "${name}: outbound cannot combine internet with domain grants"
        ++ map (entry: "${name}: outbound entry \"${entry.text}\": ${entry.error}") (
          lib.filter (entry: entry.error != null) entries
        )
        # a deny narrows a domain grant; one that no grant covers denies
        # nothing and is a typo, one that equals a grant empties it
        ++ map (pattern: "${name}: outbound entry \"!${pattern}\" denies the whole grant \"${pattern}\"") (
          lib.filter (pattern: lib.elem pattern options.allowedDomains) options.deniedDomains
        )
        ++
          map
            (
              pattern: "${name}: outbound entry \"!${pattern}\" denies nothing: no domain grant covers ${pattern}"
            )
            (
              lib.filter (
                pattern:
                !lib.elem pattern options.allowedDomains
                && !lib.any (allowed: domainCovers allowed (lib.removePrefix "*." pattern)) options.allowedDomains
              ) options.deniedDomains
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
          lib.filter (error: error != null) (map credentialDomainError granted)
          ++ lib.concatMap credentialAllowErrors granted
        )
        ++ map (domain: "${name}: credential domain ${domain} granted twice") (
          duplicates (map (credential: credential.domain) granted)
        )
        ++ map (port: "${name}: inbound port ${toString port} declared twice") (duplicates guest.expose);
    in
    guest
    // {
      inherit guest errors;
      memoryMax = options.memoryMax or (memoryMaxOf options.mem);
      inherit (options)
        id
        cpuQuota
        maxConnections
        checkpoints
        egress
        allowedDomains
        deniedDomains
        hostPorts
        secrets
        allowedTCPDestinations
        ;
      proxy = proxyOf options;
      dnsProxy = dnsProxyOf options;
      hostDns = hostDnsOf options;
      subnet = subnetOf options;
      credentials = granted;
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
