{ writers }:
writers.writeRustBin "fencr-egress-proxy" {
  rustcArgs = [
    "-O"
    "--edition"
    "2024"
  ];
} ./egress-proxy.rs
