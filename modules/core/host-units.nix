{ lib, core, ... }:
let
  inherit (core)
    userOf
    unitsOf
    vsockOf
    secretsPort
    caUnitOf
    caCertOf
    guestTrust
    hardened
    egressServiceConfig
    secretUnitOf
    checkpointUnits
    ;
in
{

  hostUnits =
    pkgs: cli: instance:
    let
      units = unitsOf instance.name;
      microvmUnit = "${units.microvm}.service";
      ca = lib.optional (instance.credentials != [ ]) "${caUnitOf instance.name}.service";
      checkpoints = checkpointUnits cli instance;
      # the socket, not the resolver: systemd connects to it while starting
      # the egress unit, which starts an instance of the service behind it
      resolvers = map (credential: "${secretUnitOf credential.name}.socket") (
        lib.filter (credential: (credential.secretCommand or null) != null) instance.credentials
      );
      secrets = instance.secrets != { } || instance.credentials != [ ];
    in
    {
      services =
        checkpoints.services
        // lib.optionalAttrs secrets {
          "${units.secrets}@" = {
            description = "raw secrets for ${instance.name}";
            after = [ microvmUnit ] ++ ca;
            requisite = [ microvmUnit ];
            requires = ca;
            partOf = [ microvmUnit ];
            unitConfig.CollectMode = "inactive-or-failed";
            # served from systemd credentials, so no secret touches the store
            # or a disk; a throwaway uid shares nothing with the hypervisor
            serviceConfig = hardened // {
              DynamicUser = true;
              StandardInput = "socket";
              StandardError = "journal";
              RestrictAddressFamilies = "none";
              LoadCredential =
                lib.mapAttrsToList (secretName: source: "${secretName}:${source}") instance.secrets
                ++ lib.optional (instance.credentials != [ ]) "${guestTrust.member}:${caCertOf instance.name}";
              ExecStart = pkgs.writeShellScript "fencr-${instance.name}-secrets" ''
                exec ${pkgs.gnutar}/bin/tar -C "$CREDENTIALS_DIRECTORY" -cf - .
              '';
            };
          };
        }
        // lib.optionalAttrs instance.egress {
          ${units.egress} = {
            description = "egress and credentials for ${instance.name}";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ] ++ ca ++ resolvers;
            requires = ca ++ resolvers;
            serviceConfig = egressServiceConfig pkgs instance;
          };
        };
      sockets = lib.optionalAttrs secrets {
        ${units.secrets} = {
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
      };
      inherit (checkpoints) timers;
    };
}
