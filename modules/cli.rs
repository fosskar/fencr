use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::os::unix::process::CommandExt;
use std::process::{Command, exit};
use std::{thread, time};

// the instance tables and tool paths are appended by cli.nix at build:
// VMS, PROXIED, CREDENTIALS, SSH, SYSTEMCTL, JOURNALCTL, NFT

/// the kind out of "fencr:<vm>:<kind>", which the firewall writes as every
/// counted rule's comment and every drop's log prefix; a kind ending in
/// blocked is a drop
fn kind<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = &line[line.find("fencr:")? + 6..];
    let rest = rest.strip_prefix(name)?.strip_prefix(':')?;
    let end = rest.find(['"', ':']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn dropped(kind: &str) -> bool {
    kind.ends_with("blocked")
}

struct Vm {
    name: &'static str,
    id: u32,
    cid: u32,
    ip: &'static str,
    egress: &'static str,
    /// how many allowedDomains the vm declares
    domains: u32,
    unit: &'static str,
}

struct Style {
    bold: &'static str,
    dim: &'static str,
    green: &'static str,
    red: &'static str,
    reset: &'static str,
}

fn style() -> Style {
    if std::io::stdout().is_terminal() {
        Style {
            bold: "\x1b[1m",
            dim: "\x1b[2m",
            green: "\x1b[32m",
            red: "\x1b[31m",
            reset: "\x1b[0m",
        }
    } else {
        Style {
            bold: "",
            dim: "",
            green: "",
            red: "",
            reset: "",
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: fencr <command> [vm-name]");
    eprintln!();
    eprintln!("  list             declared vms");
    eprintln!("  ssh <vm> [cmd]   open a shell (or run a command) in a vm");
    eprintln!("  status [vm]      vm health and traffic [--watch]; --full for systemctl");
    eprintln!("  dashboard        alias for status --watch [--once]");
    eprintln!();
    eprintln!(
        "  -H <host>        run the command on <host> over ssh (fencr must be installed there)"
    );
    exit(1)
}

fn find(name: &str) -> &'static Vm {
    VMS.iter().find(|vm| vm.name == name).unwrap_or_else(|| {
        eprintln!("fencr: unknown vm \"{name}\"");
        exit(1)
    })
}

fn fail(err: std::io::Error) -> ! {
    eprintln!("fencr: exec failed: {err}");
    exit(1)
}

/// a command's stdout, or the first line of why there is none
fn output(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if out.status.success() {
        String::from_utf8(out.stdout).map_err(|error| error.to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr)
            .lines()
            .find(|line| !line.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| out.status.to_string()))
    }
}

fn unavailable(reason: &str, s: &Style) -> String {
    format!("{}unavailable: {reason}{}", s.dim, s.reset)
}

fn print_list() {
    println!(
        "{:<16} {:<3} {:<4} {:<12} {:<7} DOMAINS",
        "NAME", "ID", "CID", "IP", "EGRESS"
    );
    for vm in VMS {
        println!(
            "{:<16} {:<3} {:<4} {:<12} {:<7} {}",
            vm.name, vm.id, vm.cid, vm.ip, vm.egress, vm.domains
        );
    }
}

fn props(unit: &str, names: &str) -> Result<BTreeMap<String, String>, String> {
    let property = format!("--property={names}");
    Ok(output(SYSTEMCTL, &["show", unit, &property])?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect())
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
    line.split(key)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
}

fn traffic(ruleset: &str, name: &str) -> (u64, u64) {
    let mut allowed = 0;
    let mut blocked = 0;
    for line in ruleset.lines() {
        let Some(kind) = kind(line, name) else {
            continue;
        };
        let packets = field(line, "packets ")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if dropped(kind) {
            blocked += packets;
        } else {
            allowed += packets;
        }
    }
    (allowed, blocked)
}

/// the kernel's log lines for the vm's drop rules on every chain
fn recent_denied(kernel: &str, name: &str) -> Option<String> {
    let mut hits: BTreeMap<String, u64> = BTreeMap::new();
    for line in kernel.lines() {
        if !kind(line, name).is_some_and(dropped) {
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

fn domains(name: &str, s: &Style) -> String {
    let Some((_, unit)) = PROXIED.iter().find(|p| p.0 == name) else {
        return format!("{}none declared{}", s.dim, s.reset);
    };
    let log = match output(
        JOURNALCTL,
        &["-u", unit, "-q", "-n", "400", "--no-pager", "-o", "cat"],
    ) {
        Ok(log) => log,
        Err(reason) => return unavailable(&reason, s),
    };
    // the egress proxy logs one line per connection: "allow <host>",
    // "intercept <host>" for a credential's domain, "deny <host>", or
    // "deny: <reason>" when there was no server name
    let mut seen: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for line in log.lines() {
        if let Some(host) = line.strip_prefix("allow ") {
            seen.entry(host.to_string()).or_default().0 += 1;
        } else if let Some(host) = line.strip_prefix("intercept ") {
            seen.entry(host.to_string()).or_default().1 += 1;
        } else if let Some(host) = line.strip_prefix("deny ") {
            seen.entry(host.to_string()).or_default().2 += 1;
        }
    }
    if seen.is_empty() {
        return format!("{}no requests observed{}", s.dim, s.reset);
    }
    let mut result = String::new();
    for (host, (allowed, intercepted, refused)) in &seen {
        if *allowed > 0 {
            let _ = write!(
                result,
                "{}\u{2713} {host} ({allowed}){}  ",
                s.green, s.reset
            );
        }
        if *intercepted > 0 {
            let _ = write!(
                result,
                "{}\u{2713} {host} ({intercepted}, credential){}  ",
                s.green, s.reset
            );
        }
        if *refused > 0 {
            let _ = write!(result, "{}\u{2717} {host} ({refused}){}  ", s.red, s.reset);
        }
    }
    result.trim_end().to_string()
}

fn unit_health(p: &Result<BTreeMap<String, String>, String>, s: &Style) -> String {
    let p = match p {
        Ok(p) => p,
        Err(reason) => return unavailable(reason, s),
    };
    match p.get("LoadState").map(String::as_str) {
        Some("not-found") | None => format!("{}MISSING{}", s.red, s.reset),
        _ => match p.get("ActiveState").map(String::as_str) {
            Some("active") => format!("{}RUNNING{}", s.green, s.reset),
            Some("failed") => format!("{}FAILED{}", s.red, s.reset),
            _ => format!("{}STOPPED{}", s.red, s.reset),
        },
    }
}

fn service_lines(name: &str, s: &Style, out: &mut Vec<String>) {
    let mut services = Vec::new();
    for (vm, unit) in PROXIED {
        if *vm == name {
            services.push(format!(
                "egress proxy {}",
                unit_health(&props(unit, "LoadState,ActiveState"), s)
            ));
        }
    }
    for (vm, unit) in CREDENTIALS {
        if *vm == name {
            services.push(format!(
                "credential {}",
                unit_health(&props(unit, "LoadState,ActiveState"), s)
            ));
        }
    }
    if !services.is_empty() {
        out.push(format!("Services: {}", services.join(", ")));
    }
}

fn render_vm(
    vm: &Vm,
    ruleset: &Result<String, String>,
    kernel: &Result<String, String>,
    s: &Style,
    out: &mut Vec<String>,
) {
    let p = props(vm.unit, "LoadState,ActiveState,MemoryCurrent");
    let state = unit_health(&p, s);
    let memory = p
        .as_ref()
        .ok()
        .and_then(|p| p.get("MemoryCurrent"))
        .and_then(|value| value.parse::<u64>().ok())
        .map(|bytes| format!("  memory {}", human(bytes)))
        .unwrap_or_default();
    out.push(format!(
        "{}{}{}  {state}  {}{memory}",
        s.bold, vm.name, s.reset, vm.ip
    ));
    out.push(format!(
        "Internet: {}{}{}",
        s.bold,
        vm.egress.to_uppercase(),
        s.reset
    ));
    out.push(String::new());
    out.push("Traffic:".to_string());
    match ruleset {
        Ok(ruleset) => {
            let (allowed, blocked) = traffic(ruleset, vm.name);
            out.push(format!(
                "  {}allowed{}  {allowed} packets",
                s.green, s.reset
            ));
            let recent = match kernel {
                Ok(kernel) => recent_denied(kernel, vm.name)
                    .map(|peers| format!("  (recent: {peers})"))
                    .unwrap_or_default(),
                Err(reason) => format!("  (recent: {})", unavailable(reason, s)),
            };
            out.push(format!(
                "  {}blocked{}  {blocked} packets{recent}",
                s.red, s.reset
            ));
        }
        Err(reason) => out.push(format!("  {}", unavailable(reason, s))),
    }
    out.push(String::new());
    out.push(format!("Domains: {}", domains(vm.name, s)));
    service_lines(vm.name, s, out);
    out.push(String::new());
}

fn render(s: &Style, only: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let ruleset = output(NFT, &["list", "ruleset"]);
    let kernel = output(
        JOURNALCTL,
        &[
            "-k",
            "-q",
            "-n",
            "400",
            "--no-pager",
            "-g",
            "fencr:",
            "-o",
            "cat",
        ],
    );
    for vm in VMS
        .iter()
        .filter(|vm| only.map(|name| name == vm.name).unwrap_or(true))
    {
        render_vm(vm, &ruleset, &kernel, s, &mut out);
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
        print!(
            "{}refreshing every 2s - ctrl-c to quit{}\x1b[K\x1b[0J",
            s.dim, s.reset
        );
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
        fail(
            Command::new(SSH)
                .arg("-t")
                .arg(host)
                .arg("fencr")
                .args(&args[2..])
                .exec(),
        );
    }
    match args.first().map(String::as_str) {
        Some("list") => print_list(),
        Some("dashboard") => show(None, !args.iter().any(|a| a == "--once")),
        Some("ssh") => {
            let name = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
            let vm = find(name);
            fail(
                Command::new(SSH)
                    .arg("-o")
                    .arg("StrictHostKeyChecking=accept-new")
                    .arg(format!("root@{}", vm.ip))
                    .args(&args[2..])
                    .exec(),
            );
        }
        Some("status") => {
            let name = args
                .get(1)
                .filter(|arg| !arg.starts_with('-'))
                .map(String::as_str);
            if let Some(name) = name {
                find(name);
            }
            if args.iter().any(|a| a == "--full") {
                let vm = name.map(find).unwrap_or_else(|| usage());
                let units = PROXIED
                    .iter()
                    .chain(CREDENTIALS)
                    .filter(|(owner, _)| *owner == vm.name)
                    .map(|(_, unit)| *unit);
                fail(
                    Command::new(SYSTEMCTL)
                        .arg("status")
                        .arg(vm.unit)
                        .args(units)
                        .arg("--no-pager")
                        .exec(),
                );
            }
            show(name, args.iter().any(|a| a == "--watch"));
        }
        _ => usage(),
    }
}
