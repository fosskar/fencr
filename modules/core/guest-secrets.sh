#!@runtimeShell@
# the vsock device comes up with udev, so the fetch retries until it is there
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

if [ -n "@storeBundle@" ]; then
  install -D -m 0444 /run/agent-secrets/@member@ @cert@
  rm /run/agent-secrets/@member@
  cat "@storeBundle@" @cert@ > @bundle@
  chmod 0444 @bundle@
fi
