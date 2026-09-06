{ core, ... }:
let
  inherit (core)
    userOf
    vsockOf
    vsockForwardBin
    forwardHardening
    proxyHardening
    ;
in
{

  vsockForwardBin =
    pkgs:
    pkgs.writers.writeRustBin "fencr-vsock-forward" {
      rustcArgs = [
        "-O"
        "--edition"
        "2024"
      ];
    } ./vsock-forward.rs;

  # host to guest ("expose"), both ends in one place: the host socket unit and
  # the per-connection relay that splice an accepted tcp connection to the
  # guest's vsock port, and the guest listener that hands it to loopback.
  # the guest end cannot tell host clients apart: group kvm reaches the
  # guest port directly through the vm's vsock socket, and listenAddress
  # only narrows the tcp side
  exposeUnits = {
    socket = instance: forward: {
      description = "forward to ${instance.name} guest port ${toString forward.guestPort}";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "${forward.listenAddress}:${toString forward.listenPort}";
        Accept = true;
        MaxConnections = 64;
      };
    };
    service = pkgs: instance: vmUnit: forward: {
      description = "forward to ${instance.name} guest port ${toString forward.guestPort}";
      after = [ vmUnit ];
      requisite = [ vmUnit ];
      partOf = [ vmUnit ];
      unitConfig.CollectMode = "inactive-or-failed";
      serviceConfig = forwardHardening // {
        ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward connect ${vsockOf instance.name} ${toString forward.guestPort}";
      };
    };
    guest = pkgs: forward: {
      name = "fencr-vsock-proxy-${toString forward.guestPort}";
      value = {
        description = "vsock proxy for port ${toString forward.guestPort}";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = proxyHardening // {
          ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:${toString forward.guestPort},fork TCP:127.0.0.1:${toString forward.guestPort}";
        };
      };
    };
  };

  # guest to host, the mirror image: a guest loopback listener relayed to the
  # host's cid, the host's socket unit on the path firecracker opens for that
  # port, and a relay that splices the connection to a host loopback port.
  # the socket belongs to the vm's user with no group or other access, so
  # only that vm's firecracker can open it: the path is the identity
  hostForwardUnits = {
    socket = instance: forward: {
      description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "${vsockOf instance.name}_${toString forward.vsockPort}";
        SocketUser = userOf instance.name;
        SocketMode = "0600";
        Accept = true;
        MaxConnections = 64;
        TriggerLimitIntervalSec = 0;
      };
    };
    service = pkgs: instance: vmUnit: forward: {
      description = "host forward for ${instance.name} vsock port ${toString forward.vsockPort}";
      after = [ vmUnit ];
      requisite = [ vmUnit ];
      partOf = [ vmUnit ];
      unitConfig.CollectMode = "inactive-or-failed";
      serviceConfig = forwardHardening // {
        ExecStart = "${vsockForwardBin pkgs}/bin/fencr-vsock-forward serve ${toString forward.targetPort}";
      };
    };
    guest = pkgs: forward: {
      name = "fencr-vsock-host-proxy-${toString forward.targetPort}";
      value = {
        description = "host vsock proxy for port ${toString forward.targetPort}";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = proxyHardening // {
          ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:${toString forward.targetPort},bind=127.0.0.1,fork VSOCK-CONNECT:2:${toString forward.vsockPort}";
        };
      };
    };
  };
}
