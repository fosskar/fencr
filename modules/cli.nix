# the fencr command: read-only convenience over the declared instances.
# mutation stays with nixos-rebuild. the instance table is baked at eval,
# so the binary needs no manifest and no daemon.
{
  lib,
  pkgs,
  instances,
  units,
}:
let
  vmRow =
    name: cfg:
    ''("${name}", ${toString cfg.id}, ${toString cfg.cid}, "${cfg.ip}", "${cfg.egress}", ${toString (lib.length cfg.allowedDomains)}, "${units.${name}.unitNames.vm}"),'';

  socketRows =
    name: unitSet:
    map (socket: ''
      ("${name}", "${socket.unit}", "${socket.label}"),
    '') unitSet.unitNames.sockets;

  proxiedRows = name: unitSet: map (unit: ''("${name}", "${unit}"),'') unitSet.unitNames.proxy;

  brokerRows = name: unitSet: map (unit: ''("${name}", "${unit}"),'') unitSet.unitNames.brokers;
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
    use std::collections::BTreeMap;
    use std::env;
    use std::fmt::Write as _;
    use std::io::{IsTerminal, Write as _};
    use std::os::unix::process::CommandExt;
    use std::process::{exit, Command};
    use std::{thread, time};

    // name, id, cid, ip, egress, allowed domain count, vm unit
    static VMS: &[(&str, u32, u32, &str, &str, u32, &str)] = &[
    ${lib.concatStrings (lib.mapAttrsToList vmRow instances)}
    ];

    // vm, socket unit, human label
    static SOCKETS: &[(&str, &str, &str)] = &[
    ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList socketRows units))}
    ];

    // vm, egress proxy unit
    static PROXIED: &[(&str, &str)] = &[
    ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList proxiedRows units))}
    ];

    // vm, broker unit
    static BROKERS: &[(&str, &str)] = &[
    ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList brokerRows units))}
    ];

    const SOCAT: &str = "${pkgs.socat}/bin/socat";
    const SSH: &str = "${pkgs.openssh}/bin/ssh";
    const SYSTEMCTL: &str = "${pkgs.systemd}/bin/systemctl";
    const JOURNALCTL: &str = "${pkgs.systemd}/bin/journalctl";
    const NFT: &str = "${pkgs.nftables}/bin/nft";

    type Vm = (&'static str, u32, u32, &'static str, &'static str, u32, &'static str);

    struct Style {
        bold: &'static str,
        dim: &'static str,
        green: &'static str,
        red: &'static str,
        reset: &'static str,
    }

    fn style() -> Style {
        if std::io::stdout().is_terminal() {
            Style { bold: "\x1b[1m", dim: "\x1b[2m", green: "\x1b[32m", red: "\x1b[31m", reset: "\x1b[0m" }
        } else {
            Style { bold: "", dim: "", green: "", red: "", reset: "" }
        }
    }

    fn usage() -> ! {
        eprintln!("usage: fencr <command> [vm-name]");
        eprintln!();
        eprintln!("  list             declared vms");
        eprintln!("  ssh <vm> [cmd]   open a shell (or run a command) in a vm");
        eprintln!("  proxy <vm>       stdio splice to the vm's vsock sshd, for ProxyCommand");
        eprintln!("  status [vm]      vm health and traffic [--watch]; --full for systemctl");
        eprintln!("  dashboard        alias for status --watch [--once]");
        eprintln!();
        eprintln!("  -H <host>        run the command on <host> over ssh (fencr must be installed there)");
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

    fn props(unit: &str, names: &str) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let property = format!("--property={names}");
        if let Some(text) = output(SYSTEMCTL, &["show", unit, &property]) {
            for line in text.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    map.insert(key.to_string(), value.to_string());
                }
            }
        }
        map
    }

    fn human(bytes: u64) -> String {
        if bytes >= 1 << 30 {
            format!("{:.1}G", bytes as f64 / (1u64 << 30) as f64)
        } else if bytes >= 1 << 20 {
            format!("{}M", bytes >> 20)
        } else {
            format!("{}K", bytes >> 10)
        }
    }

    fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        line.split(key).nth(1).and_then(|rest| rest.split_whitespace().next())
    }

    fn traffic(ruleset: &str, name: &str) -> (u64, u64) {
        let mut allowed = 0;
        let mut blocked = 0;
        for line in ruleset.lines() {
            let Some(pos) = line.find("comment \"fencr:") else { continue };
            let tag = &line[pos + 15..];
            let Some(end) = tag.find('"') else { continue };
            let Some((vm, kind)) = tag[..end].split_once(':') else { continue };
            if vm != name {
                continue;
            }
            let packets = line
                .find("packets ")
                .map(|p| &line[p + 8..])
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            if kind.contains("blocked") {
                blocked += packets;
            } else {
                allowed += packets;
            }
        }
        (allowed, blocked)
    }

    fn recent_denied(kernel: &str, name: &str) -> Option<String> {
        let net = format!("fencr-{name}-blocked:");
        let host = format!("fencr-{name}-host-blocked:");
        let mut hits: BTreeMap<String, u64> = BTreeMap::new();
        for line in kernel.lines() {
            if !line.contains(&net) && !line.contains(&host) {
                continue;
            }
            let dst = field(line, "DST=").unwrap_or("?");
            let proto = field(line, "PROTO=").unwrap_or("?").to_lowercase();
            let key = match field(line, "DPT=") {
                Some(port) => format!("{dst}:{port}/{proto}"),
                None => format!("{dst}/{proto}"),
            };
            *hits.entry(key).or_default() += 1;
        }
        let mut sorted: Vec<_> = hits.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        if sorted.is_empty() {
            None
        } else {
            let mut result = String::new();
            for (index, (peer, count)) in sorted.iter().take(3).enumerate() {
                if index > 0 {
                    result.push_str(", ");
                }
                let _ = write!(result, "{peer} x{count}");
            }
            Some(result)
        }
    }

    fn domains(name: &str, egress: &str, s: &Style) -> String {
        let Some((_, unit)) = PROXIED.iter().find(|p| p.0 == name) else {
            return format!("{}unavailable with {egress} egress{}", s.dim, s.reset);
        };
        let Some(log) = output(JOURNALCTL, &["-u", unit, "-q", "-n", "400", "--no-pager", "-o", "cat"]) else {
            return format!("{}journal access denied{}", s.dim, s.reset);
        };
        let mut seen: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for line in log.lines() {
            if let Some(rest) = line.split("): CONNECT ").nth(1) {
                if let Some(hostport) = rest.split_whitespace().next() {
                    let host = hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport);
                    seen.entry(host.to_string()).or_default().0 += 1;
                }
            }
            if let Some(rest) = line.split("filtered domain \"").nth(1) {
                if let Some(host) = rest.split('"').next() {
                    seen.entry(host.to_string()).or_default().1 += 1;
                }
            }
        }
        if seen.is_empty() {
            return format!("{}no requests observed{}", s.dim, s.reset);
        }
        let mut result = String::new();
        for (host, (requests, refused)) in &seen {
            let allowed = requests.saturating_sub(*refused);
            if allowed > 0 {
                let _ = write!(result, "{}\u{2713} {host} ({allowed}){}  ", s.green, s.reset);
            }
            if *refused > 0 {
                let _ = write!(result, "{}\u{2717} {host} ({refused}){}  ", s.red, s.reset);
            }
        }
        result.trim_end().to_string()
    }

    fn unit_health(p: &BTreeMap<String, String>, s: &Style) -> String {
        match p.get("LoadState").map(String::as_str) {
            Some("not-found") | None => format!("{}MISSING{}", s.red, s.reset),
            _ => match p.get("ActiveState").map(String::as_str) {
                Some("active") => format!("{}RUNNING{}", s.green, s.reset),
                Some("failed") => format!("{}FAILED{}", s.red, s.reset),
                _ => format!("{}STOPPED{}", s.red, s.reset),
            },
        }
    }

    fn connection_lines(name: &str, s: &Style, out: &mut Vec<String>) {
        for (vm, unit, label) in SOCKETS {
            if *vm != name {
                continue;
            }
            let p = props(unit, "LoadState,ActiveState,NAccepted,NConnections");
            let state = match p.get("LoadState").map(String::as_str) {
                Some("not-found") | None => format!("{}MISSING{}", s.red, s.reset),
                _ if p.get("ActiveState").map(String::as_str) != Some("active") => {
                    format!("{}NOT LISTENING{}", s.red, s.reset)
                }
                _ => {
                    let accepted = p.get("NAccepted").map(String::as_str).unwrap_or("?");
                    let active = p.get("NConnections").map(String::as_str).unwrap_or("?");
                    format!("{}{active} active{} ({accepted} total)", s.green, s.reset)
                }
            };
            out.push(format!("  {label}  {state}"));
        }
    }

    fn service_lines(name: &str, s: &Style, out: &mut Vec<String>) {
        let mut services = Vec::new();
        for (vm, unit) in PROXIED {
            if *vm == name {
                services.push(format!("egress proxy {}", unit_health(&props(unit, "LoadState,ActiveState"), s)));
            }
        }
        for (vm, unit) in BROKERS {
            if *vm == name {
                services.push(format!("credential broker {}", unit_health(&props(unit, "LoadState,ActiveState"), s)));
            }
        }
        if !services.is_empty() {
            out.push(format!("Services: {}", services.join(", ")));
        }
    }

    fn render_vm(vm: &Vm, ruleset: Option<&str>, kernel: &str, s: &Style, out: &mut Vec<String>) {
        let p = props(vm.6, "LoadState,ActiveState,MemoryCurrent");
        let state = unit_health(&p, s);
        let memory = p
            .get("MemoryCurrent")
            .and_then(|value| value.parse::<u64>().ok())
            .map(|bytes| format!("  memory {}", human(bytes)))
            .unwrap_or_default();
        out.push(format!("{}{}{}  {state}  {}{memory}", s.bold, vm.0, s.reset, vm.3));
        out.push(format!("Internet: {}{}{}", s.bold, vm.4.to_uppercase(), s.reset));
        out.push(String::new());
        out.push("Traffic:".to_string());
        match ruleset {
            Some(ruleset) => {
                let (allowed, blocked) = traffic(ruleset, vm.0);
                out.push(format!("  {}allowed{}  {allowed} packets", s.green, s.reset));
                let recent = recent_denied(kernel, vm.0)
                    .map(|peers| format!("  (recent: {peers})"))
                    .unwrap_or_default();
                out.push(format!("  {}blocked{}  {blocked} packets{recent}", s.red, s.reset));
            }
            None => out.push(format!("  {}unavailable: nft requires root{}", s.dim, s.reset)),
        }
        out.push(String::new());
        out.push("Connections:".to_string());
        connection_lines(vm.0, s, out);
        out.push(String::new());
        out.push(format!("Domains: {}", domains(vm.0, vm.4, s)));
        service_lines(vm.0, s, out);
        out.push(String::new());
    }

    fn render(s: &Style, only: Option<&str>) -> Vec<String> {
        let mut out = Vec::new();
        let ruleset = output(NFT, &["list", "ruleset"]);
        let kernel = output(JOURNALCTL, &["-k", "-q", "-n", "400", "--no-pager", "-g", "fencr-", "-o", "cat"])
            .unwrap_or_default();
        for vm in VMS.iter().filter(|vm| only.map(|name| name == vm.0).unwrap_or(true)) {
            render_vm(vm, ruleset.as_deref(), &kernel, s, &mut out);
        }
        if VMS.is_empty() {
            out.push("(no vms declared)".to_string());
        }
        out
    }

    fn show(only: Option<&str>, watch: bool) {
        let s = style();
        if !watch {
            for line in render(&s, only) {
                println!("{line}");
            }
            return;
        }
        print!("\x1b[2J");
        loop {
            print!("\x1b[H");
            for line in render(&s, only) {
                print!("{line}\x1b[K\n");
            }
            print!("{}refreshing every 2s - ctrl-c to quit{}\x1b[K\x1b[0J", s.dim, s.reset);
            let _ = std::io::stdout().flush();
            thread::sleep(time::Duration::from_secs(2));
        }
    }

    fn main() {
        let args: Vec<String> = env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("-H") {
            if args.len() < 3 {
                usage();
            }
            let host = args[1].clone();
            // -t so remote `fencr ssh` gets a tty; harmless for the rest
            fail(Command::new(SSH)
                .arg("-t")
                .arg(host)
                .arg("fencr")
                .args(&args[2..])
                .exec());
        }
        match args.first().map(String::as_str) {
            Some("list") => print_list(),
            Some("dashboard") => show(None, !args.iter().any(|a| a == "--once")),
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
                let name = args.get(1).filter(|arg| !arg.starts_with('-')).map(String::as_str);
                if let Some(name) = name {
                    find(name);
                }
                if args.iter().any(|a| a == "--full") {
                    let vm = name.map(find).unwrap_or_else(|| usage());
                    fail(Command::new(SYSTEMCTL)
                        .arg("status")
                        .arg(vm.6)
                        .arg(format!("{}-*", vm.0))
                        .arg("--no-pager")
                        .exec());
                }
                show(name, args.iter().any(|a| a == "--watch"));
            }
            _ => usage(),
        }
    }
  ''
