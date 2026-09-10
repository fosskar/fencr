// the one rule for what a domain pattern covers, appended to the source of
// the cli and the egress proxy at build so both judge names alike

/// `*.example.com` covers the names below example.com, not example.com
/// itself; anything else covers exactly itself. host names have no case
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
