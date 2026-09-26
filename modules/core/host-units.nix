{ lib, core, ... }:
let
  inherit (core)
    unitsOf
    vsockOf
    secretsPort
    trustPort
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
      secrets = instance.secrets != { };
      trusted = instance.credentials != [ ];
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
              LoadCredential = lib.mapAttrsToList (
                secretName: source: "${secretName}:${source}"
              ) instance.secrets;
              ExecStart = pkgs.writeShellScript "fencr-${instance.name}-secrets" ''
                exec ${pkgs.gnutar}/bin/tar -C "$CREDENTIALS_DIRECTORY" -cf - .
              '';
            };
          };
        }
        // lib.optionalAttrs trusted {
          # the authority is what makes the interception work, so it travels
          # with the credentials rather than among the guest's raw secrets
          "${units.trust}@" = {
            description = "certificate authority for ${instance.name}";
            after = [ microvmUnit ] ++ ca;
            requisite = [ microvmUnit ];
            requires = ca;
            partOf = [ microvmUnit ];
            unitConfig.CollectMode = "inactive-or-failed";
            serviceConfig = hardened // {
              DynamicUser = true;
              StandardInput = "socket";
              StandardError = "journal";
              RestrictAddressFamilies = "none";
              LoadCredential = [ "${guestTrust.member}:${caCertOf instance.name}" ];
              ExecStart = pkgs.writeShellScript "fencr-${instance.name}-trust" ''
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
      # no SocketUser: pid 1 would chown the socket by path after binding it,
      # in a directory the sandbox's user owns and can swap a symlink into.
      # that directory's 0700 is what keeps other users off the socket
      sockets =
        lib.optionalAttrs trusted {
          ${units.trust} = {
            description = "certificate authority for ${instance.name}";
            wantedBy = [ "sockets.target" ];
            socketConfig = {
              ListenStream = "${vsockOf instance.name}_${toString trustPort}";
              SocketMode = "0666";
              Accept = true;
              MaxConnections = 4;
            };
          };
        }
        // lib.optionalAttrs secrets {
          ${units.secrets} = {
            description = "raw secrets for ${instance.name}";
            wantedBy = [ "sockets.target" ];
            socketConfig = {
              ListenStream = "${vsockOf instance.name}_${toString secretsPort}";
              SocketMode = "0666";
              Accept = true;
              MaxConnections = 4;
            };
          };
        };
      inherit (checkpoints) timers;
    };
}
