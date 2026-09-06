{ lib, core, ... }:
let
  inherit (core)
    userOf
    vmUnitOf
    vsockOf
    secretsPort
    caUnit
    caCert
    forwardHardening
    egressProxyServiceConfig
    credentialServiceConfig
    ;
in
{

  hostUnits =
    pkgs: instance:
    let
      vmUnit = vmUnitOf instance.name;
      proxyName = "fencr-${instance.name}-egress-proxy";
      credentialsName = "fencr-${instance.name}-credentials";
      credentialUnits = lib.optional (instance.credentials != [ ]) "${credentialsName}.service";
      credentialServices = lib.optionalAttrs (instance.credentials != [ ]) {
        ${credentialsName} = {
          description = "credentials for ${instance.name}";
          wantedBy = [ "multi-user.target" ];
          requires = [ caUnit ];
          after = [ caUnit ];
          serviceConfig = credentialServiceConfig pkgs instance;
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
        credentialServices
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
      sockets = secretsUnits.socket or { };
      # what the guest system is built against
      inherit (instance) guest;
      unitNames = {
        vm = vmUnit;
        proxy = lib.optional instance.proxy "${proxyName}.service";
        credentials = credentialUnits;
      };
    };
}
