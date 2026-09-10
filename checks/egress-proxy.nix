_self: pkgs:

# the egress proxy's parsers on canned bytes: the client hello walk, the
# allowlist and the resolver, without a vm
let
  source = pkgs.writeText "egress-proxy-test.rs" (
    builtins.readFile ../pkgs/egress-proxy/egress-proxy.rs + builtins.readFile ../pkgs/domain.rs
  );
in
pkgs.runCommandCC "fencr-egress-proxy-check" { nativeBuildInputs = [ pkgs.rustc ]; } ''
  rustc --test --edition 2024 ${source} -o proxy-test
  ./proxy-test
  touch "$out"
''
