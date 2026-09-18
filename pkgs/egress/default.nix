{ buildGoModule, runCommand }:
buildGoModule {
  pname = "fencr-egress";
  version = "0";
  # domain.go is shared with the command, so the wildcard rule has one
  # definition rather than a twin per language
  src = runCommand "fencr-egress-src" { } ''
    mkdir -p "$out"
    cp ${./go.mod} "$out/go.mod"
    cp ${./main.go} "$out/main.go"
    cp ${./dns.go} "$out/dns.go"
    cp ${./sni.go} "$out/sni.go"
    cp ${./credentials.go} "$out/credentials.go"
    cp ${../domain.go} "$out/domain.go"
    cp ${./config_test.go} "$out/config_test.go"
    cp ${./dns_test.go} "$out/dns_test.go"
    cp ${./egress_test.go} "$out/egress_test.go"
    cp ${./credentials_test.go} "$out/credentials_test.go"
    cp ${./splice_test.go} "$out/splice_test.go"
  '';
  # the standard library is the whole dependency tree
  vendorHash = null;
  # no cgo: the closure is the binary, and go's own resolver reads
  # resolv.conf for an https upstream
  env.CGO_ENABLED = 0;
  meta.mainProgram = "fencr-egress";
}
