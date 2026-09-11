{ buildGoModule }:
buildGoModule {
  pname = "fencr-credentials-proxy";
  version = "0";
  src = ./.;
  # the standard library is the whole dependency tree
  vendorHash = null;
  # no cgo: the closure is the binary, and go's own resolver reads
  # resolv.conf for an https upstream
  env.CGO_ENABLED = 0;
  meta.mainProgram = "credentials-proxy";
}
