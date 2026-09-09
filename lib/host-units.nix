{ lib, core, ... }:
let
  inherit (core)
    userOf
    unitsOf
    vsockOf
    secretsPort
    caUnit
    caCert
    guestTrust
    hardened
    egressProxyServiceConfig
    credentialServiceConfig
    ;
in
{

  hostUnits =
    pkgs: instance:
    let
      units = unitsOf instance.name;
      vmUnit = "${units.vm}.service";
      caService = "${caUnit}.service";
      credentialUnits = lib.optional (instance.credentials != [ ]) "${units.credentials}.service";
      credentialServices = lib.optionalAttrs (instance.credentials != [ ]) {
        ${units.credentials} = {
          description = "credentials for ${instance.name}";
          wantedBy = [ "multi-user.target" ];
          requires = [ caService ];
          after = [ caService ];
          serviceConfig = credentialServiceConfig pkgs instance;
        };
      };
      # raw secrets, served once per boot as a tar stream of the unit's
      # credentials directory into a connection the guest opened; the
      # host's ca certificate rides along for a vm with a credential
      secretsUnits = lib.optionalAttrs (instance.secrets != { } || instance.credentials != [ ]) {
        socket.${units.secrets} = {
          description = "raw secrets for ${instance.name}";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenStream = "${vsockOf instance.name}_${toString secretsPort}";
            SocketUser = userOf instance.name;
            SocketMode = "0600";
            Accept = true;
            MaxConnections = 4;
          };
        };
        service."${units.secrets}@" = {
          description = "raw secrets for ${instance.name}";
          after = [ vmUnit ] ++ lib.optional (instance.credentials != [ ]) caService;
          requisite = [ vmUnit ];
          requires = lib.optional (instance.credentials != [ ]) caService;
          partOf = [ vmUnit ];
          unitConfig.CollectMode = "inactive-or-failed";
          # a throwaway uid: a bug in tar shares nothing with the hypervisor
          serviceConfig = hardened // {
            DynamicUser = true;
            StandardInput = "socket";
            StandardError = "journal";
            RestrictAddressFamilies = "none";
            LoadCredential =
              lib.mapAttrsToList (secretName: source: "${secretName}:${source}") instance.secrets
              ++ lib.optional (instance.credentials != [ ]) "${guestTrust.member}:${caCert}";
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
          ${units.proxy} = {
            description = "egress proxy for ${instance.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ] ++ credentialUnits;
            wants = credentialUnits;
            serviceConfig = egressProxyServiceConfig pkgs instance;
          };
        };
      sockets = secretsUnits.socket or { };
      unitNames = {
        vm = vmUnit;
        proxy = lib.optional instance.proxy "${units.proxy}.service";
        credentials = credentialUnits;
      };
    };
}
