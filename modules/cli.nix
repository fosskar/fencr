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

  brokerRows =
    name: cfg:
    map (forward: ''
      ("${name}", "${name}-broker-${toString forward.vsockPort}.service", "broker 127.0.0.1:${toString forward.broker.port} -> ${toString forward.targetPort}"),
    '') (lib.filter (forward: forward.broker != null) cfg.hostForwards);
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

    // vm, broker unit, human label
    static BROKERS: &[(&str, &str, &str)] = &[
    ${lib.concatStrings (lib.concatLists (lib.mapAttrsToList brokerRows instances))}
    ];

    const SOCAT: &str = "${pkgs.socat}/bin/socat";
    const SSH: &str = "${pkgs.openssh}/bin/ssh";
    const SYSTEMCTL: &str = "${pkgs.systemd}/bin/systemctl";
    const JOURNALCTL: &str = "${pkgs.systemd}/bin/journalctl";
    const NFT: &str = "${pkgs.nftables}/bin/nft";

    type Vm = (&'static str, u32, u32, &'static str, &'static str, u32);

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
        eprintln!("  status <vm>      one line per unit; --full for raw systemctl status");
        eprintln!("  dashboard        per-vm traffic, domains and denied peers [--once]");
        eprintln!("  update <vm>      delegate to flakelet update (errors on a declarative install)");
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

    // one line per unit: colored state dot, substate, socket counters,
    // memory for the vm itself
    fn status_line(unit: &str, label: &str, s: &Style) -> String {
        let p = props(unit, "ActiveState,SubState,NAccepted,NConnections,MemoryCurrent");
        let active = p.get("ActiveState").map(String::as_str).unwrap_or("?");
        let sub = p.get("SubState").map(String::as_str).unwrap_or("?");
        let dot = match active {
            "active" => format!("{}\u{25cf}{}", s.green, s.reset),
            "failed" => format!("{}\u{25cf}{}", s.red, s.reset),
            _ => format!("{}\u{25cb}{}", s.dim, s.reset),
        };
        let mut extra = String::new();
        if let Some(accepted) = p.get("NAccepted") {
            let now = p.get("NConnections").map(String::as_str).unwrap_or("0");
            let _ = write!(extra, "  {accepted} accepted, {now} active");
        }
        if let Some(Ok(bytes)) = p.get("MemoryCurrent").map(|m| m.parse::<u64>()) {
            let _ = write!(extra, "  mem {}", human(bytes));
        }
        format!("  {dot} {label:<44} {sub}{extra}")
    }

    fn print_status(vm: &Vm, s: &Style) {
        println!("{}{}{}  {}  cid {}  egress {}", s.bold, vm.0, s.reset, vm.3, vm.2, vm.4);
        println!("{}", status_line(&format!("microvm@{}.service", vm.0), "vm", s));
        for (name, unit, label) in SOCKETS {
            if *name == vm.0 {
                println!("{}", status_line(unit, label, s));
            }
        }
        for (name, unit) in PROXIED {
            if *name == vm.0 {
                println!("{}", status_line(unit, "egress proxy", s));
            }
        }
        for (name, unit, label) in BROKERS {
            if *name == vm.0 {
                println!("{}", status_line(unit, label, s));
            }
        }
    }

    // counter rules carry `comment "fencr:<vm>:<kind>"`; parse the text
    // ruleset rather than -j so no json machinery is needed. zero counters
    // are noise and stay hidden.
    fn counter_lines(ruleset: &str, name: &str, s: &Style, out: &mut Vec<String>) {
        let mut allowed = String::new();
        let mut blocked = String::new();
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
                .unwrap_or("0");
            if packets == "0" {
                continue;
            }
            if kind.contains("blocked") {
                let short = kind.replace("-blocked", "").replace("blocked-", "").replace("blocked", "all");
                let _ = write!(blocked, "  {short} {packets}");
            } else {
                let _ = write!(allowed, "  {kind} {packets}");
            }
        }
        if allowed.is_empty() && blocked.is_empty() {
            out.push(format!("  {}no traffic counted yet{}", s.dim, s.reset));
        }
        if !allowed.is_empty() {
            out.push(format!("  {}allowed{} {allowed}", s.green, s.reset));
        }
        if !blocked.is_empty() {
            out.push(format!("  {}blocked{} {blocked}", s.red, s.reset));
        }
    }

    fn forward_lines(name: &str, s: &Style, out: &mut Vec<String>) {
        for (vm, unit, label) in SOCKETS {
            if *vm != name {
                continue;
            }
            let p = props(unit, "NAccepted,NConnections");
            let accepted = p.get("NAccepted").map(String::as_str).unwrap_or("?");
            let active = p.get("NConnections").map(String::as_str).unwrap_or("?");
            out.push(format!("  {}forward{}  {label:<36} {accepted:>5}/{active}", s.dim, s.reset));
        }
    }

    // the egress proxy logs every CONNECT and every filter refusal; fold
    // its journal into a per-domain allowed/refused tally
    fn domain_lines(name: &str, s: &Style, out: &mut Vec<String>) {
        let Some((_, unit)) = PROXIED.iter().find(|p| p.0 == name) else { return };
        let Some(log) = output(JOURNALCTL, &["-u", unit, "-q", "-n", "400", "--no-pager", "-o", "cat"]) else {
            out.push(format!("  {}domains: no journal access{}", s.dim, s.reset));
            return;
        };
        // domain -> (requests, refused)
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
            return;
        }
        let mut line = "  domains".to_string();
        for (host, (requests, refused)) in &seen {
            let allowed = requests.saturating_sub(*refused);
            if allowed > 0 {
                let _ = write!(line, "  {}\u{2713} {host} {allowed}{}", s.green, s.reset);
            }
            if *refused > 0 {
                let _ = write!(line, "  {}\u{2717} {host} {refused}{}", s.red, s.reset);
            }
        }
        out.push(line);
    }

    fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        line.split(key).nth(1).and_then(|rest| rest.split_whitespace().next())
    }

    // the firewall logs each drop with prefix fencr-<vm>[-host]-blocked:;
    // aggregate by destination instead of echoing raw kernel lines
    fn denied_lines(kernel: &str, name: &str, s: &Style, out: &mut Vec<String>) {
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
        if hits.is_empty() {
            return;
        }
        let mut sorted: Vec<_> = hits.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        let mut line = format!("  {}denied{} ", s.red, s.reset);
        for (key, count) in sorted.iter().take(4) {
            let _ = write!(line, "  {key} x{count}");
        }
        out.push(line);
    }

    fn render(s: &Style) -> Vec<String> {
        let mut out = Vec::new();
        let ruleset = output(NFT, &["list", "ruleset"]);
        let kernel = output(JOURNALCTL, &["-k", "-q", "-n", "400", "--no-pager", "-g", "fencr-", "-o", "cat"])
            .unwrap_or_default();
        for vm in VMS {
            let name = vm.0;
            let running = props(&format!("microvm@{name}.service"), "ActiveState")
                .get("ActiveState")
                .map(String::as_str)
                .unwrap_or("?")
                == "active";
            let dot = if running {
                format!("{}\u{25cf}{}", s.green, s.reset)
            } else {
                format!("{}\u{25cb}{}", s.red, s.reset)
            };
            out.push(format!("{dot} {}{name}{}  {}  egress {}", s.bold, s.reset, vm.3, vm.4));
            match &ruleset {
                None => out.push(format!("  {}counters need root (nft list ruleset refused){}", s.dim, s.reset)),
                Some(ruleset) => counter_lines(ruleset, name, s, &mut out),
            }
            forward_lines(name, s, &mut out);
            domain_lines(name, s, &mut out);
            denied_lines(&kernel, name, s, &mut out);
            out.push(String::new());
        }
        if VMS.is_empty() {
            out.push("(no vms declared)".to_string());
        }
        out
    }

    fn dashboard(once: bool) {
        let s = style();
        if once {
            for line in render(&s) {
                println!("{line}");
            }
            return;
        }
        // redraw in place: home the cursor, clear each line's tail, then
        // clear whatever the previous frame left below. no full-screen
        // wipes, so no flicker and no scrollback spam.
        print!("\x1b[2J");
        loop {
            print!("\x1b[H");
            for line in render(&s) {
                print!("{line}\x1b[K\n");
            }
            print!("{}refreshing every 2s - ctrl-c to quit{}\x1b[K\x1b[0J", s.dim, s.reset);
            let _ = std::io::stdout().flush();
            thread::sleep(time::Duration::from_secs(2));
        }
    }

    fn flakelet_path() -> Option<String> {
        let path = env::var("PATH").ok()?;
        path.split(':')
            .map(|dir| format!("{dir}/flakelet"))
            .find(|candidate| std::path::Path::new(candidate).is_file())
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
                if args.iter().any(|a| a == "--full") {
                    fail(Command::new(SYSTEMCTL)
                        .arg("status")
                        .arg(format!("microvm@{}.service", vm.0))
                        .arg(format!("{}-*", vm.0))
                        .arg("--no-pager")
                        .exec());
                }
                print_status(vm, &style());
            }
            Some("update") => {
                // flakelet owns its namespace, so the name passes through
                // unchecked against the baked table
                let name = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
                match flakelet_path() {
                    Some(flakelet) => fail(Command::new(flakelet).arg("update").arg(name).exec()),
                    None => {
                        eprintln!("fencr: no flakelet on this host; the sandbox is part of the");
                        eprintln!("system configuration. change it there and run nixos-rebuild.");
                        exit(1)
                    }
                }
            }
            _ => usage(),
        }
    }
  ''
