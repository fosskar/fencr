{ lib, core, ... }:
let
  inherit (core)
    userOf
    vmUnitOf
    vsockOf
    sshSocketOf
    secretsPort
    caUnit
    caCert
    vsockForwardBin
    forwardHardening
    exposeUnits
    hostForwardUnits
    egressProxyServiceConfig
    credentialServiceConfig
    ;
in
{

  hostUnits =
    pkgs: instance:
    let
      vmUnit = vmUnitOf instance.name;
      forwardName = forward: "fencr-${instance.name}-forward-${toString forward.listenPort}";
      hostForwardName = forward: "fencr-${instance.name}-host-forward-${toString forward.vsockPort}";
      proxyName = "fencr-${instance.name}-egress-proxy";
      credentialsName = "fencr-${instance.name}-credentials";
      credentialUnits = lib.optional (instance.credentials != [ ]) "${credentialsName}.service";
      forwardServices = map (forward: {
        name = "${forwardName forward}@";
        value = exposeUnits.service pkgs instance vmUnit forward;
      }) instance.expose;
      hostForwardServices = map (forward: {
        name = "${hostForwardName forward}@";
        value = hostForwardUnits.service pkgs instance vmUnit forward;
      }) instance.hostForwards;
      credentialServices = lib.optional (instance.credentials != [ ]) {
        name = credentialsName;
        value = {
          description = "credentials for ${instance.name}";
          wantedBy = [ "multi-user.target" ];
          requires = [ caUnit ];
          after = [ caUnit ];
          serviceConfig = credentialServiceConfig pkgs instance;
        };
      };
      forwardSockets = map (forward: {
        name = forwardName forward;
        value = exposeUnits.socket instance forward;
      }) instance.expose;
      hostForwardSockets = map (forward: {
        name = hostForwardName forward;
        value = hostForwardUnits.socket instance forward;
      }) instance.hostForwards;
      # the ssh door: a socket every host account may open, relayed into
      # the guest's vsock port 22; the key check happens in the guest
      sshName = "fencr-${instance.name}-ssh";
      sshUnits = lib.optionalAttrs (instance.sshKeys != [ ]) {
        socket.${sshName} = {
          description = "ssh into ${instance.name}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = sshSocketOf instance.name;
            SocketMode = "0666";
            Accept = true;
            MaxConnections = 16;
          };
        };
        service."${sshName}@" = {
          description = "ssh into ${instance.name}";
          after = [ vmUnit ];
          requisite = [ vmUnit ];
          partOf = [ vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          serviceConfig = forwardHardening // {
            ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward connect ${vsockOf instance.name} 22";
          };
        };
      };
      # raw secrets, served once per boot as a tar stream of the unit's
      # credentials directory into a connection the guest opened; the
      # host's ca certificate rides along for a vm with a credential
      secretsName = "fencr-${instance.name}-secrets";
      secretsUnits = lib.optionalAttrs (instance.secrets != { } || instance.credentials != [ ]) {
        socket.${secretsName} = {
          description = "raw secrets for ${instance.name}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = "${vsockOf instance.name}_${toString secretsPort}";
            SocketUser = userOf instance.name;
            SocketMode = "0600";
            Accept = true;
            MaxConnections = 4;
            TriggerLimitIntervalSec = 0;
          };
        };
        service."${secretsName}@" = {
          description = "raw secrets for ${instance.name}";
          after = [ vmUnit ] ++ lib.optional (instance.credentials != [ ]) caUnit;
          requisite = [ vmUnit ];
          requires = lib.optional (instance.credentials != [ ]) caUnit;
          partOf = [ vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          serviceConfig = forwardHardening // {
            LoadCredential =
              lib.mapAttrsToList (secretName: source: "${secretName}:${source}") instance.secrets
              ++ lib.optional (instance.credentials != [ ]) "fencr-ca.crt:${caCert}";
            ExecStart = pkgs.writeShellScript "fencr-${instance.name}-secrets" ''
              exec ${pkgs.gnutar}/bin/tar -C "$CREDENTIALS_DIRECTORY" -cf - .
            '';
          };
        };
      };
    in
    {
      services =
        lib.listToAttrs (forwardServices ++ hostForwardServices ++ credentialServices)
        // sshUnits.service or { }
        // secretsUnits.service or { }
        // lib.optionalAttrs instance.proxy {
          ${proxyName} = {
            description = "egress proxy for ${instance.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ] ++ credentialUnits;
            wants = credentialUnits;
            serviceConfig = egressProxyServiceConfig pkgs instance;
          };
        };
      sockets =
        lib.listToAttrs (forwardSockets ++ hostForwardSockets)
        // sshUnits.socket or { }
        // secretsUnits.socket or { };
      # what the guest system is built against
      inherit (instance) guest;
      unitNames = {
        vm = vmUnit;
        sockets =
          map (forward: {
            unit = "${forwardName forward}.socket";
            label = "host -> guest: ${forward.listenAddress}:${toString forward.listenPort} -> guest ${toString forward.guestPort}";
          }) instance.expose
          ++ map (forward: {
            unit = "${hostForwardName forward}.socket";
            label = "guest -> host: vsock ${toString forward.vsockPort} -> host ${toString forward.targetPort}";
          }) instance.hostForwards
          ++ lib.optional (instance.sshKeys != [ ]) {
            unit = "${sshName}.socket";
            label = "host -> guest: ssh";
          };
        proxy = lib.optional instance.proxy "${proxyName}.service";
        credentials = credentialUnits;
      };
    };
}
