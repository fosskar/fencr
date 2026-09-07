#!@runtimeShell@
# fetch the vm's secrets, and the host's certificate authority when a
# credential is granted, as one tar stream over vsock; the vsock device
# comes up with udev, so the fetch waits for it
set -eu

install -d -m 0700 /run/agent-secrets
for _ in $(seq 60); do
  if @socat@ -u VSOCK-CONNECT:2:@port@ - \
      | @tar@ -C /run/agent-secrets -xf - --no-same-owner --no-same-permissions; then
    break
  fi
  sleep 0.5
done
test -e /run/agent-secrets/@first@
chmod 0400 /run/agent-secrets/*

# the system trust store, the store bundle with the host's authority
# appended, on every path environment.etc points at /run/fencr; the
# authority alone for node
if [ -n "@storeBundle@" ]; then
  install -d -m 0755 /run/fencr
  install -m 0444 /run/agent-secrets/fencr-ca.crt /run/fencr/ca.crt
  rm /run/agent-secrets/fencr-ca.crt
  cat "@storeBundle@" /run/fencr/ca.crt > /run/fencr/ca-bundle.crt
  chmod 0444 /run/fencr/ca-bundle.crt
fi
