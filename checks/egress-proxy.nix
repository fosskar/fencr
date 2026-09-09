_self: pkgs:

# the egress proxy's parsers on canned bytes: the client hello walk, the
# allowlist and the resolver, without a vm
pkgs.runCommandCC "fencr-egress-proxy-check" { nativeBuildInputs = [ pkgs.rustc ]; } ''
  rustc --test --edition 2024 ${../pkgs/egress-proxy/egress-proxy.rs} -o proxy-test
  ./proxy-test
  touch "$out"
''
