#!@runtimeShell@
# one vsock port, one directory. the device comes up with udev and this runs
# before sysinit.target, so the fetch retries until it is there
set -eu

install -d -m @mode@ @dir@
for _ in $(seq 60); do
  if @socat@ -u VSOCK-CONNECT:2:@port@ - \
      | @tar@ -C @dir@ -xf - --no-same-owner --no-same-permissions; then
    break
  fi
  sleep 0.5
done
test -e @dir@/@first@
chmod @fileMode@ @dir@/*
