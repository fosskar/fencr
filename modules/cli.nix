# the fencr command: read-only convenience over the declared instances.
# mutation stays with the real control planes (nixos-rebuild, flakelet
# update). the instance table is baked at eval, so the binary needs no
# manifest and no daemon.
{
  lib,
  pkgs,
  core,
  instances,
}:
let
  vmRow =
    name: cfg:
    ''("${name}", ${toString cfg.id}, ${toString (core.cidOf cfg)}, "${cfg.ip}", "${cfg.egress}", ${toString (lib.length cfg.allowedDomains)}),'';

  socketRows =
    name: cfg:
    map (forward: ''
      ("${name}", "${name}-forward-${toString forward.listenPort}.socket", "in  ${forward.listenAddress}:${toString forward.listenPort} -> guest ${toString forward.guestPort}"),
    '') cfg.expose
    ++ map (forward: ''
      ("${name}", "${name}-host-forward-${toString forward.vsockPort}.socket", "out vsock ${toString forward.vsockPort} -> host ${toString forward.targetPort}"),
    '') (core.hostForwardsOf cfg);

  proxiedRows =
    name: cfg: lib.optional (core.proxyOf cfg != null) ''("${name}", "${name}-egress-proxy.service"),'';
in
pkgs.writers.writeRustBin "fencr"
  {
    rustcArgs = [
      "-O"
      "--edition"
      "2021"
    ];
  }
  ''
    use std::env;
    use std::os::unix::process::CommandExt;
    use std::process::{exit, Command};
    use std::{thread, time};

    // name, id, cid, ip, egress, allowed domain count
    static VMS: &[(&str, u32, u32, &str, &str, u32)] = &[
    ${lib.concatStrings (lib.mapAttrsToList vmRow instances)}
    ];

    // vm, socket unit, human label
    static SOCKETS: &[(&str, &str, &str)] = &[
    ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList socketRows instances))}
    ];

    // vm, egress proxy unit
    static PROXIED: &[(&str, &str)] = &[
    ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList proxiedRows instances))}
    ];

    const SOCAT: &str = "${pkgs.socat}/bin/socat";
    const SSH: &str = "${pkgs.openssh}/bin/ssh";
    const SYSTEMCTL: &str = "${pkgs.systemd}/bin/systemctl";
    const JOURNALCTL: &str = "${pkgs.systemd}/bin/journalctl";
    const NFT: &str = "${pkgs.nftables}/bin/nft";

    type Vm = (&'static str, u32, u32, &'static str, &'static str, u32);

    fn usage() -> ! {
        eprintln!("usage: fencr <command> [vm-name]");
        eprintln!();
        eprintln!("  list             declared vms");
        eprintln!("  ssh <vm> [cmd]   open a shell (or run a command) in a vm");
        eprintln!("  proxy <vm>       stdio splice to the vm's vsock sshd, for ProxyCommand");
        eprintln!("  status <vm>      the vm unit and its forward/proxy/broker units");
        eprintln!("  dashboard        live traffic view: allowed, blocked, ingress [--once]");
        eprintln!("  update           where updates actually happen");
        exit(1)
    }

    fn find(name: &str) -> &'static Vm {
        VMS.iter().find(|vm| vm.0 == name).unwrap_or_else(|| {
            eprintln!("fencr: unknown vm \"{name}\"");
            exit(1)
        })
    }

    fn fail(err: std::io::Error) -> ! {
        eprintln!("fencr: exec failed: {err}");
        exit(1)
    }

    fn output(cmd: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(cmd).args(args).output().ok()?;
        if out.status.success() {
            String::from_utf8(out.stdout).ok()
        } else {
            None
        }
    }

    fn print_list() {
        println!("{:<16} {:<3} {:<4} {:<12} {:<7} DOMAINS", "NAME", "ID", "CID", "IP", "EGRESS");
        for vm in VMS {
            println!("{:<16} {:<3} {:<4} {:<12} {:<7} {}", vm.0, vm.1, vm.2, vm.3, vm.4, vm.5);
        }
    }

    // counter rules carry `comment "fencr:<vm>:<kind>"`; parse the text
    // ruleset rather than -j so no json machinery is needed
    fn print_counters() {
        println!("TRAFFIC (packets per rule)");
        let Some(ruleset) = output(NFT, &["list", "ruleset"]) else {
            println!("  (needs root: nft list ruleset was refused)");
            return;
        };
        let mut any = false;
        for line in ruleset.lines() {
            let Some(pos) = line.find("comment \"fencr:") else { continue };
            let tag = &line[pos + 15..];
            let Some(end) = tag.find('"') else { continue };
            let tag = &tag[..end];
            let packets = line
                .find("packets ")
                .map(|p| &line[p + 8..])
                .and_then(|rest| rest.split_whitespace().next())
                .unwrap_or("0");
            let marker = if tag.contains("blocked") { "!" } else { " " };
            println!("  {marker} {tag:<40} {packets}");
            any = true;
        }
        if !any {
            println!("  (no fencr counters in the ruleset)");
        }
    }

    fn print_sockets() {
        println!("FORWARDS (accepted total / active now)");
        for (vm, unit, label) in SOCKETS {
            let stats = output(SYSTEMCTL, &["show", unit, "--property=NAccepted,NConnections"]);
            let (mut accepted, mut active) = ("?".to_string(), "?".to_string());
            if let Some(stats) = stats {
                for kv in stats.lines() {
                    if let Some(v) = kv.strip_prefix("NAccepted=") {
                        accepted = v.to_string();
                    }
                    if let Some(v) = kv.strip_prefix("NConnections=") {
                        active = v.to_string();
                    }
                }
            }
            println!("  {vm:<16} {label:<40} {accepted:>6} / {active}");
        }
        if SOCKETS.is_empty() {
            println!("  (no forwards declared)");
        }
    }

    fn print_blocked() {
        println!("RECENT BLOCKS (kernel log)");
        match output(JOURNALCTL, &["-k", "-q", "-n", "10", "--no-pager", "-g", "fencr-"]) {
            Some(lines) if !lines.trim().is_empty() => {
                for line in lines.lines() {
                    println!("  {line}");
                }
            }
            Some(_) => println!("  (none)"),
            None => println!("  (no journal access: run as root or join systemd-journal)"),
        }
        for (vm, unit) in PROXIED {
            println!("EGRESS PROXY {vm} (last requests)");
            match output(JOURNALCTL, &["-u", unit, "-q", "-n", "6", "--no-pager", "-o", "cat"]) {
                Some(lines) if !lines.trim().is_empty() => {
                    for line in lines.lines() {
                        println!("  {line}");
                    }
                }
                Some(_) => println!("  (quiet)"),
                None => println!("  (no journal access)"),
            }
        }
    }

    fn dashboard(once: bool) {
        loop {
            if !once {
                print!("\x1b[2J\x1b[H");
            }
            print_list();
            println!();
            print_counters();
            println!();
            print_sockets();
            println!();
            print_blocked();
            if once {
                return;
            }
            println!();
            println!("refreshing every 2s - ctrl-c to quit");
            thread::sleep(time::Duration::from_secs(2));
        }
    }

    fn main() {
        let args: Vec<String> = env::args().skip(1).collect();
        match args.first().map(String::as_str) {
            Some("list") => print_list(),
            Some("dashboard") => dashboard(args.iter().any(|a| a == "--once")),
            Some("ssh") => {
                let name = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
                let vm = find(name);
                let proxy = format!("ProxyCommand={SOCAT} - VSOCK-CONNECT:{}:22", vm.2);
                fail(Command::new(SSH)
                    .arg("-o").arg(proxy)
                    .arg("-o").arg("StrictHostKeyChecking=accept-new")
                    .arg(format!("root@{name}"))
                    .args(&args[2..])
                    .exec());
            }
            Some("proxy") => {
                let name = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
                let vm = find(name);
                fail(Command::new(SOCAT)
                    .arg("-")
                    .arg(format!("VSOCK-CONNECT:{}:22", vm.2))
                    .exec());
            }
            Some("status") => {
                let name = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
                let vm = find(name);
                fail(Command::new(SYSTEMCTL)
                    .arg("status")
                    .arg(format!("microvm@{}.service", vm.0))
                    .arg(format!("{}-*", vm.0))
                    .arg("--no-pager")
                    .exec());
            }
            Some("update") => {
                eprintln!("fencr owns no update path. on this host the sandbox is part of the");
                eprintln!("system configuration: change it there and run nixos-rebuild. on a");
                eprintln!("flakelet host, the sandbox updates with: flakelet update <name>");
                exit(1)
            }
            _ => usage(),
        }
    }
  ''
