use std::collections::BTreeMap;
use std::env;
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

/// where a grant's use shows: the counter of the rule tagged with the kind,
/// or the proxy log's lines for hosts a pattern covers, a deny pattern
/// refused or a credential's domain. a host's table may use no grant of
/// some source
#[allow(dead_code)]
enum Source {
    Counter(&'static str),
    Domain(&'static str),
    Denied(&'static str),
    Credential(&'static str),
}

struct Grant {
    text: &'static str,
    source: Source,
}

struct Vm {
    name: &'static str,
    id: u32,
    cid: u32,
    ip: &'static str,
    host_ip: &'static str,
    inbound: &'static [Grant],
    outbound: &'static [Grant],
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
    eprintln!("  status [vm]      vm health and traffic [--watch]; --full <vm> for systemctl");
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

fn grant_summary(grants: &[Grant]) -> String {
    if grants.is_empty() {
        "denied".to_string()
    } else {
        grants
            .iter()
            .map(|grant| grant.text)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn print_list() {
    println!(
        "{:<16} {:<3} {:<4} {:<12} INBOUND / OUTBOUND",
        "NAME", "ID", "CID", "IP"
    );
    for vm in VMS {
        println!(
            "{:<16} {:<3} {:<4} {:<12} {} / {}",
            vm.name,
            vm.id,
            vm.cid,
            vm.ip,
            grant_summary(vm.inbound),
            grant_summary(vm.outbound)
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

/// the packet count of the vm's rule tagged with the kind
fn packets(ruleset: &str, name: &str, tag: &str) -> u64 {
    ruleset
        .lines()
        .filter(|line| kind(line, name) == Some(tag))
        .filter_map(|line| field(line, "packets "))
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

/// "*.example.com" covers the names below example.com, not example.com
fn covers(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
        None => pattern == host,
    }
}

/// the egress proxy logs one line per connection: "allow <host>",
/// "intercept <host>" for a credential's domain, "deny <host>", or
/// "deny: <reason>" when there was no server name
fn proxy_log(name: &str) -> Option<Result<String, String>> {
    let (_, unit) = PROXIED.iter().find(|p| p.0 == name)?;
    Some(output(
        JOURNALCTL,
        &["-u", unit, "-q", "-n", "400", "--no-pager", "-o", "cat"],
    ))
}

fn connections(log: &str, verb: &str, matches: impl Fn(&str) -> bool) -> u64 {
    log.lines()
        .filter_map(|line| line.strip_prefix(verb))
        .filter(|host| matches(host))
        .count() as u64
}

fn plural(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("{count} {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

fn grant_line(grant: &Grant, use_count: Result<u64, String>, unit: &str, s: &Style) -> String {
    match use_count {
        Ok(0) => format!("  {}\u{b7} {:<40}  unused{}", s.dim, grant.text, s.reset),
        Ok(count) => format!(
            "  {}\u{2713}{} {:<40}  {}",
            s.green,
            s.reset,
            grant.text,
            plural(count, unit)
        ),
        Err(reason) => format!("  \u{b7} {:<40}  {}", grant.text, unavailable(&reason, s)),
    }
}

fn grant_lines(
    vm: &Vm,
    grants: &[Grant],
    ruleset: &Result<String, String>,
    proxy: &Option<Result<String, String>>,
    s: &Style,
    out: &mut Vec<String>,
) {
    for grant in grants {
        let line = match &grant.source {
            Source::Counter(tag) => grant_line(
                grant,
                ruleset
                    .as_ref()
                    .map(|ruleset| packets(ruleset, vm.name, tag))
                    .map_err(Clone::clone),
                "packet",
                s,
            ),
            Source::Domain(pattern) => grant_line(
                grant,
                proxy
                    .as_ref()
                    .expect("a domain grant runs the egress proxy")
                    .as_ref()
                    .map(|log| connections(log, "allow ", |host| covers(pattern, host)))
                    .map_err(Clone::clone),
                "connection",
                s,
            ),
            Source::Denied(pattern) => grant_line(
                grant,
                proxy
                    .as_ref()
                    .expect("a deny entry runs the egress proxy")
                    .as_ref()
                    .map(|log| connections(log, "deny ", |host| covers(pattern, host)))
                    .map_err(Clone::clone),
                "connection",
                s,
            ),
            Source::Credential(domain) => grant_line(
                grant,
                proxy
                    .as_ref()
                    .expect("a credential runs the egress proxy")
                    .as_ref()
                    .map(|log| connections(log, "intercept ", |host| host == *domain))
                    .map_err(Clone::clone),
                "connection",
                s,
            ),
        };
        out.push(line);
    }
}

/// what the firewall and the proxy refused, by peer, with the grant that
/// would admit it
fn blocked(vm: &Vm, kernel: &str, proxy: Option<&str>) -> Vec<(String, u64)> {
    let mut hits: BTreeMap<(String, String), u64> = BTreeMap::new();
    for line in kernel.lines() {
        let Some(kind) = kind(line, vm.name).filter(|kind| dropped(kind)) else {
            continue;
        };
        let dst = field(line, "DST=").unwrap_or("?");
        // multicast is link chatter (igmp reports, mdns); no grant applies
        if dst
            .split('.')
            .next()
            .and_then(|octet| octet.parse::<u8>().ok())
            .is_some_and(|octet| (224..=239).contains(&octet))
        {
            continue;
        }
        let proto = field(line, "PROTO=").unwrap_or("?").to_lowercase();
        let port = field(line, "DPT=");
        // a reply toward the host's ephemeral range: the connection the host
        // opened is no longer tracked, so its replies miss ct state
        let ephemeral = port
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port >= 32768);
        let peer = |target: &str| match port {
            Some(port) => format!("{target}:{port}/{proto}"),
            None => format!("{target}/{proto}"),
        };
        let (flow, hint) = match (kind, port) {
            ("connections-blocked", _) => (
                format!("guest \u{2192} {}", peer(dst)),
                "over maxConnections".to_string(),
            ),
            ("guest-blocked", Some(port)) => (
                format!("host  \u{2192} {}", peer("guest")),
                format!("inbound {port}"),
            ),
            ("guest-blocked", None) => (format!("host  \u{2192} {}", peer("guest")), String::new()),
            ("host-blocked", Some("53")) if dst == vm.host_ip => (
                format!("guest \u{2192} {}", peer("host")),
                "outbound \"internet\" or a domain".to_string(),
            ),
            ("host-blocked", Some(_)) if ephemeral => (
                format!("guest \u{2192} {}", peer("host")),
                "reply to a connection the host no longer tracks".to_string(),
            ),
            ("host-blocked", Some(port)) if proto == "tcp" => (
                format!("guest \u{2192} {}", peer("host")),
                format!("outbound \"host:{port}\""),
            ),
            ("host-blocked", _) => (format!("guest \u{2192} {}", peer("host")), String::new()),
            (_, Some(port)) if proto == "tcp" => (
                format!("guest \u{2192} {}", peer(dst)),
                format!("outbound \"{dst}:{port}\""),
            ),
            _ => (format!("guest \u{2192} {}", peer(dst)), String::new()),
        };
        *hits.entry((flow, hint)).or_default() += 1;
    }
    for host in proxy
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|line| line.strip_prefix("deny "))
    {
        // a host a deny entry refused is listed under that entry, not as
        // a missing grant
        let denied = vm.outbound.iter().find_map(|grant| match grant.source {
            Source::Denied(pattern) if covers(pattern, host) => Some(pattern),
            _ => None,
        });
        let key = (
            format!("guest \u{2192} {host}:443/tls"),
            match denied {
                Some(pattern) => format!("denied by outbound \"!{pattern}\""),
                None => format!("outbound \"{host}\""),
            },
        );
        *hits.entry(key).or_default() += 1;
    }
    let mut sorted: Vec<_> = hits.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sorted
        .into_iter()
        .map(|((flow, hint), count)| (format!("{flow:<32}  x{count:<4}  {hint}"), count))
        .collect()
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

/// the kernel's drop log since the vm unit last started, or the last 400
/// lines when the unit reports no start
fn kernel_log(started: Option<&str>) -> Result<String, String> {
    let mut args = vec!["-k", "-q", "--no-pager", "-g", "fencr:", "-o", "cat"];
    match started {
        Some(started) => args.extend(["--since", started]),
        None => args.extend(["-n", "400"]),
    }
    // journalctl exits 1 when -g matches nothing: no denials, not a failure
    match output(JOURNALCTL, &args) {
        Err(reason) if reason == "exit status: 1" => Ok(String::new()),
        kernel => kernel,
    }
}

fn render_vm(vm: &Vm, ruleset: &Result<String, String>, s: &Style, out: &mut Vec<String>) {
    let p = props(
        vm.unit,
        "LoadState,ActiveState,MemoryCurrent,ActiveEnterTimestamp",
    );
    let state = unit_health(&p, s);
    let kernel = kernel_log(
        p.as_ref()
            .ok()
            .and_then(|p| p.get("ActiveEnterTimestamp"))
            .filter(|value| !value.is_empty())
            .map(String::as_str),
    );
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
    let proxy = proxy_log(vm.name);
    for (heading, grants) in [
        ("Inbound (from host)", vm.inbound),
        ("Outbound (otherwise denied)", vm.outbound),
    ] {
        out.push(format!("{heading}:"));
        if grants.is_empty() {
            out.push("  denied".to_string());
        } else {
            grant_lines(vm, grants, ruleset, &proxy, s, out);
        }
    }
    out.push(String::new());
    out.push("Blocked (journal):".to_string());
    match &kernel {
        Ok(kernel) => {
            let proxy = match &proxy {
                Some(Ok(log)) => Some(log.as_str()),
                _ => None,
            };
            let hits = blocked(vm, kernel, proxy);
            if hits.is_empty() {
                out.push(format!("  {}none{}", s.dim, s.reset));
            }
            for (entry, _) in hits.iter().take(8) {
                out.push(format!(
                    "  {}\u{2717}{} {}",
                    s.red,
                    s.reset,
                    entry.trim_end()
                ));
            }
        }
        Err(reason) => out.push(format!("  {}", unavailable(reason, s))),
    }
    out.push(String::new());
    service_lines(vm.name, s, out);
    out.push(String::new());
}

fn render(s: &Style, only: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let ruleset = output(NFT, &["list", "ruleset"]);
    for vm in VMS
        .iter()
        .filter(|vm| only.map(|name| name == vm.name).unwrap_or(true))
    {
        render_vm(vm, &ruleset, s, &mut out);
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
            // the module's Host <vm> alias carries the address, root and
            // the host key policy
            let name = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
            fail(
                Command::new(SSH)
                    .arg(find(name).name)
                    .args(&args[2..])
                    .exec(),
            );
        }
        Some("status") => {
            let vm = args
                .get(1)
                .filter(|arg| !arg.starts_with('-'))
                .map(|name| find(name));
            if args.iter().any(|a| a == "--full") {
                let vm = vm.unwrap_or_else(|| usage());
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
            show(vm.map(|vm| vm.name), args.iter().any(|a| a == "--watch"));
        }
        _ => usage(),
    }
}
