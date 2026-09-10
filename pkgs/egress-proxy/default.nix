{ writers }:
writers.writeRustBin "fencr-egress-proxy" {
  rustcArgs = [
    "-O"
    "--edition"
    "2024"
  ];
} (builtins.readFile ./egress-proxy.rs + builtins.readFile ../domain.rs)
