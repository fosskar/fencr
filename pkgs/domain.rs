// appended to the cli's and the egress proxy's source at build, so both
// judge names alike; instance.nix carries the same rule for eval time

/// `*.example.com` covers the names below example.com, not example.com itself
fn covers(pattern: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
        None => pattern == host,
    }
}
