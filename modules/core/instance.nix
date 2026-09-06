{ lib, core, ... }:
let
  inherit (core)
    defaults
    tapOf
    bridgeOf
    macOf
    cidOf
    hostIpOf
    ipOf
    subnetOf
    stateDirOf
    runDirOf
    parseDestination
    parseExpose
    dnsProxyOf
    proxyOf
    credentialsOf
    credentialDomainError
    domainPatternErrors
    duplicates
    ;
in
{
  # applied again in resolveInstance, so a check that omits an option still
  # gets the same vm the module would build
  defaults = {
    vcpu = 4;
    mem = 4096;
    memoryMax = "4608M";
    cpuQuota = "400%";
    stateSize = 32768;
    egress = "closed";
    prefixLength = 24;
    credentials = [ ];
    allowedDomains = [ ];
    allowedTCPDestinations = [ ];
    expose = [ ];
    hostPorts = [ ];
    secrets = { };
  };

  tapOf = name: "tap-${name}";
  bridgeOf = name: "br-${name}";
  macOf = cfg: "02:00:00:00:20:0${toString (cfg.id + 1)}";
  cidOf = cfg: 3 + cfg.id;
  hostIpOf = cfg: "10.30.${toString (cfg.id + 1)}.1";
  ipOf = cfg: "10.30.${toString (cfg.id + 1)}.2";
  subnetOf = cfg: "10.30.${toString (cfg.id + 1)}.0/24";

  stateDirOf = name: "/var/lib/fencr-vms/${name}";
  stateImageOf = name: "${stateDirOf name}/state.img";
  userOf = name: "fencr-${name}";
  vmUnitOf = name: "fencr-${name}.service";
  # firecracker's vsock on the host: one unix socket for connections into
  # the guest, and one per port, "<vsock>_<port>", for connections out of
  # it. the directory admits the vm's user and group kvm, which is what the
  # relays run with; nobody else on the host reaches a vm this way
  runDirOf = name: "/run/fencr-${name}";
  vsockOf = name: "${runDirOf name}/vsock";
  # the power button: a guest listener on this vsock port powers off on any
  # connection, and only the vm's user and group kvm can open the vsock
  powerPort = 4;
  # raw secrets: at boot the guest fetches them as one archive from a host
  # socket only the vm's own user can open; the host side reads them as
  # systemd credentials, so they touch neither the store nor a disk
  secretsPort = 5;

  # "<ipv4[/prefix]>:<port>" sugar for destination entries. hostnames need
  # runtime resolution and stay unsupported until name-based egress exists.
  parseDestination =
    value:
    if builtins.isAttrs value then
      value
    else
      let
        matched = builtins.match "([0-9./]+):([0-9]+)" value;
      in
      if matched == null then
        throw "fencr: destination \"${value}\" is not <ipv4[/prefix]>:<port>; hostnames are not supported yet"
      else
        {
          address = builtins.elemAt matched 0;
          port = lib.toInt (builtins.elemAt matched 1);
        };

  # an exposed port is a guest port the host may reach at the guest's
  # address; a string is the same port spelled out
  parseExpose =
    value:
    if builtins.isInt value then
      value
    else if builtins.match "[0-9]+" value != null then
      lib.toInt value
    else
      throw "fencr: expose entry \"${value}\" is not a port";

  duplicates =
    values: lib.unique (lib.filter (value: lib.count (other: other == value) values > 1) values);

  resolveInstance =
    {
      name,
      sshKeys ? [ ],
      credentials ? { },
      ...
    }@args:
    let
      options = defaults // args.options;
      granted = credentialsOf options credentials;
      guest = {
        inherit name sshKeys;
        inherit (options)
          vcpu
          mem
          stateSize
          prefixLength
          ;
        # with a domain allowlist the egress proxy is the guest's resolver
        dns = if dnsProxyOf options then hostIpOf options else options.dns;
        tap = tapOf name;
        bridge = bridgeOf name;
        mac = macOf options;
        cid = cidOf options;
        hostIp = hostIpOf options;
        ip = ipOf options;
        expose = map parseExpose options.expose;
        credentialDomains = map (credential: credential.domain) granted;
        secretNames = lib.attrNames options.secrets;
      };
      errors =
        lib.optional (options.id < 0 || options.id > 8) "${name}: id must be between 0 and 8"
        ++ map (
          secretName:
          "${name}: secret name \"${secretName}\" contains characters unsupported by systemd credentials"
        ) (lib.filter (secretName: builtins.match "[A-Za-z0-9_.-]+" secretName == null) guest.secretNames)
        ++ lib.optional (
          lib.stringLength guest.tap > 15
        ) "vm name \"${name}\" is too long: \"${guest.tap}\" exceeds IFNAMSIZ"
        ++ lib.optional (
          options.allowedDomains != [ ] && options.egress != "closed"
        ) "${name}: allowedDomains requires egress = \"closed\""
        ++ map (error: "${name}: invalid allowedDomains ${error}") (
          domainPatternErrors options.allowedDomains
        )
        ++ map (credential: "${name}: credential \"${credential}\" is not declared in fencr.credentials") (
          lib.filter (credential: !(credentials ? ${credential})) options.credentials
        )
        ++ map (error: "${name}: ${error}") (
          lib.filter (error: error != null) (map credentialDomainError granted)
        )
        ++ map (domain: "${name}: credential domain ${domain} granted twice") (
          duplicates (map (credential: credential.domain) granted)
        )
        ++ map (port: "${name}: expose port ${toString port} declared twice") (duplicates guest.expose);
    in
    guest
    // {
      inherit guest errors;
      inherit (options)
        id
        memoryMax
        cpuQuota
        egress
        allowedDomains
        hostPorts
        secrets
        ;
      allowedTCPDestinations = map parseDestination options.allowedTCPDestinations;
      proxy = proxyOf options;
      dnsProxy = dnsProxyOf options;
      subnet = subnetOf options;
      credentials = granted;
    };

  fleetErrors =
    instances:
    lib.optional (
      duplicates (map (instance: instance.id) (lib.attrValues instances)) != [ ]
    ) "instance ids must be unique";
}
