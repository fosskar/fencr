self: pkgs:

# Calls the flakelet impl directly with a stub flakelet input and asserts the
# expected units exist. Building this check builds the guest system.
let
  inherit (pkgs) lib;
  module = self.flakelets.default {
    # only impl is exercised; option declarations stay unevaluated
    types = null;
  };
  result = module.impl {
    options = {
      id = 0;
      vcpu = 2;
      mem = 1024;
      dns = "9.9.9.9";
      adminPublicKey = null;
      secrets = { };
      allowedTCPDestinations = [ "192.168.1.50:8123" ];
      expose = [
        "33627"
        {
          listenAddress = "127.0.0.1";
          listenPort = 33628;
          guestPort = 22100;
        }
      ];
      hostForwards = [
        {
          vsockPort = 18764;
          targetPort = 8764;
          broker = {
            port = 28764;
            header = "Authorization";
            secretFile = "/run/secrets/broker-token";
          };
        }
      ];
      hostPorts = [ 443 ];
      guestModules = [ ];
    };
    inputs = {
      nixpkgs = {
        inherit pkgs lib;
      };
      flakelet = {
        name = "sbx";
        storePath = path: path;
        contracts = { };
        extraModules = [ ];
      };
    };
  };
  expectedUnits = [
    "sbx"
    "fwd-33627@"
    "fwd-33628@"
    "hfwd-18764@"
    "broker-18764"
  ];
  expectedSockets = [
    "fwd-33627"
    "fwd-33628"
    "hfwd-18764"
  ];
  missing =
    lib.filter (unit: !(result.services ? ${unit})) expectedUnits
    ++ lib.filter (socket: !(result.sockets ? ${socket})) expectedSockets;
in
assert lib.assertMsg (missing == [ ]) "flakelet check: missing units ${toString missing}";
pkgs.writeText "fencr-flakelet-check" (builtins.toJSON result)
