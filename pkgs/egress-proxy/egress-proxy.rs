//! the road out for a vm with domain grants or credentials: on the bridge
//! address it answers every dns name with itself and, on the port the firewall
//! redirects 443 to, reads the server name from the tls client hello. a
//! credential's domain goes to the vm's credentials proxy on its unix
//! socket, which holds the certificate; an allowed name is spliced to the
//! real host unread, unless a deny pattern names it; the rest is refused.
use std::io::{self, Read, Write};
use std::net::{
    Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn matches(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|pattern| covers(pattern, host))
}

/// a name some allow pattern matches and no deny pattern does
fn allowed(patterns: &[String], denied: &[String], host: &str) -> bool {
    !matches(denied, host) && matches(patterns, host)
}

/// the server name of a tls client hello, or why there is none
fn server_name(hello: &[u8]) -> Result<String, &'static str> {
    let mut at = 0;
    let mut take = |n: usize| -> Result<&[u8], &'static str> {
        let slice = hello.get(at..at + n).ok_or("short hello")?;
        at += n;
        Ok(slice)
    };
    if take(1)? != [0x01] {
        return Err("not a client hello");
    }
    take(3)?; // handshake length
    take(2)?; // client version
    take(32)?; // random
    let session = take(1)?[0] as usize;
    take(session)?;
    let suites = u16::from_be_bytes(take(2)?.try_into().unwrap()) as usize;
    take(suites)?;
    let compressions = take(1)?[0] as usize;
    take(compressions)?;
    let mut extensions = u16::from_be_bytes(take(2)?.try_into().unwrap()) as usize;
    while extensions >= 4 {
        let kind = u16::from_be_bytes(take(2)?.try_into().unwrap());
        let length = u16::from_be_bytes(take(2)?.try_into().unwrap()) as usize;
        extensions = extensions.checked_sub(4 + length).ok_or("short hello")?;
        if kind != 0 {
            take(length)?;
            continue;
        }
        let list = take(length)?;
        // server_name list: length(2), then entries of type(1) length(2) name
        let entry = list.get(2..).ok_or("short server_name")?;
        if entry.first() != Some(&0) {
            return Err("server_name is not a host name");
        }
        let name_len = u16::from_be_bytes(
            entry
                .get(1..3)
                .ok_or("short server_name")?
                .try_into()
                .unwrap(),
        ) as usize;
        let name = entry.get(3..3 + name_len).ok_or("short server_name")?;
        // the name is echoed into the journal, where a newline would forge
        // a line of its own; a host name is letters, digits, "-" and "."
        if name.is_empty()
            || !name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(b))
        {
            return Err("server_name is not a host name");
        }
        return Ok(String::from_utf8_lossy(name).into_owned());
    }
    Err("no server_name")
}

/// reads whole tls records from the client until the client hello is
/// complete; the bytes are replayed to the server afterwards
fn read_client_hello(
    client: &mut TcpStream,
) -> io::Result<(Vec<u8>, Result<String, &'static str>)> {
    let mut buffer = Vec::with_capacity(4096);
    let mut hello = Vec::new();
    let mut handshake_len = None;
    loop {
        let mut record = [0u8; 5];
        client.read_exact(&mut record)?;
        if record[0] != 0x16 {
            return Ok((buffer, Err("not a tls handshake")));
        }
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;
        let mut body = vec![0u8; length];
        client.read_exact(&mut body)?;
        buffer.extend_from_slice(&record);
        buffer.extend_from_slice(&body);
        hello.extend_from_slice(&body);
        if handshake_len.is_none() && hello.len() >= 4 {
            handshake_len =
                Some(4 + u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize);
        }
        match handshake_len {
            Some(n) if hello.len() >= n => return Ok((buffer, server_name(&hello[..n]))),
            _ if buffer.len() > 65536 => return Ok((buffer, Err("client hello too large"))),
            _ => {}
        }
    }
}

/// a server end: the real host over tcp or a credential proxy over its
/// unix socket
trait Server: Read + Write + Send + 'static {
    fn duplicate(&self) -> io::Result<Self>
    where
        Self: Sized;
    fn close_write(&self) -> io::Result<()>;
}

impl Server for TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

impl Server for UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

fn splice<S: Server>(mut client: TcpStream, mut server: S) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut server_writer = server.duplicate()?;
    let server_to_client = thread::spawn(move || {
        let result = io::copy(&mut server, &mut client);
        let _ = client.shutdown(Shutdown::Write);
        result
    });
    let client_to_server = io::copy(&mut client_reader, &mut server_writer);
    let _ = server_writer.close_write();
    server_to_client
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))??;
    client_to_server?;
    Ok(())
}

fn serve_tls(
    mut client: TcpStream,
    patterns: &[String],
    denied: &[String],
    intercepts: &[String],
    socket: &str,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (hello, name) = read_client_hello(&mut client)?;
    let host = match name {
        Ok(host) => host,
        Err(reason) => {
            eprintln!("deny: {reason}");
            return Ok(());
        }
    };
    if intercepts
        .iter()
        .any(|domain| host.eq_ignore_ascii_case(domain))
    {
        eprintln!("intercept {host}");
        return relay(client, &hello, UnixStream::connect(socket)?);
    }
    if !allowed(patterns, denied, &host) {
        eprintln!("deny {host}");
        return Ok(());
    }
    eprintln!("allow {host}");
    // the unit's IPAddressDeny is what keeps an allowed name out of the lan
    let address = (host.as_str(), 443u16)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| io::Error::other(format!("{host} has no ipv4 address")))?;
    relay(
        client,
        &hello,
        TcpStream::connect_timeout(&address, Duration::from_secs(10))?,
    )
}

/// replays the client hello to the server end and splices the rest; the
/// verb is logged before the connect, so a failure follows its name
fn relay<S: Server>(client: TcpStream, hello: &[u8], mut server: S) -> io::Result<()> {
    client.set_read_timeout(None)?;
    server.write_all(hello)?;
    splice(client, server)
}

/// answers every A query with the bridge address and everything else
/// with an empty answer; the client hello names the real destination
fn serve_dns(socket: &UdpSocket, answer: Ipv4Addr) -> io::Result<()> {
    let mut query = [0u8; 512];
    loop {
        let (len, peer) = socket.recv_from(&mut query)?;
        let query = &query[..len];
        if len < 12 || query[2] & 0x80 != 0 {
            continue;
        }
        // walk the question name to find qtype
        let mut at = 12;
        while let Some(&label) = query.get(at) {
            if label == 0 {
                at += 1;
                break;
            }
            at += 1 + label as usize;
        }
        let Some(question) = query.get(12..at + 4) else {
            continue;
        };
        let qtype = &question[question.len() - 4..][..2];
        let mut reply = Vec::with_capacity(len + 16);
        reply.extend_from_slice(&query[0..2]);
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
        reply.extend_from_slice(question);
        if qtype == [0, 1] {
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            reply.extend_from_slice(&answer.octets());
        }
        // a reply that cannot be sent is that client's loss, not the resolver's
        let _ = socket.send_to(&reply, peer);
    }
}

fn lines(path: &str) -> io::Result<Vec<String>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (
        Some(dns_address),
        Some(tls_address),
        Some(allowlist),
        Some(denylist),
        Some(interceptlist),
        Some(socket),
    ) = (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    )
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fencr-egress-proxy <dns address:port> <tls address:port> <allowlist file> <denylist file> <intercept file> <credentials socket>",
        ));
    };
    let invalid = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} must be an ipv4 address:port"),
        )
    };
    let dns_address: SocketAddrV4 = dns_address.parse().map_err(|_| invalid("dns address"))?;
    let tls_address: SocketAddrV4 = tls_address.parse().map_err(|_| invalid("tls address"))?;
    let answer = *dns_address.ip();
    let patterns: Arc<Vec<String>> = Arc::new(lines(&allowlist)?);
    let denied: Arc<Vec<String>> = Arc::new(lines(&denylist)?);
    let intercepts: Arc<Vec<String>> = Arc::new(lines(&interceptlist)?);
    let socket: Arc<str> = Arc::from(socket);
    // the bridge gets its address from networkd; be there when it does
    let dns = loop {
        match UdpSocket::bind(dns_address) {
            Ok(socket) => break socket,
            Err(error) if error.raw_os_error() == Some(99) => {
                thread::sleep(Duration::from_millis(500))
            }
            Err(error) => return Err(error),
        }
    };
    thread::spawn(move || {
        if let Err(error) = serve_dns(&dns, answer) {
            eprintln!("dns: {error}");
        }
    });
    let listener = TcpListener::bind(tls_address)?;
    for client in listener.incoming() {
        let client = client?;
        let patterns = Arc::clone(&patterns);
        let denied = Arc::clone(&denied);
        let intercepts = Arc::clone(&intercepts);
        let socket = Arc::clone(&socket);
        thread::spawn(move || {
            if let Err(error) = serve_tls(client, &patterns, &denied, &intercepts, &socket) {
                eprintln!("relay: {error}");
            }
        });
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fencr-egress-proxy: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a client hello carrying the given extensions block
    fn hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut hello = vec![1];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend(body);
        hello
    }

    fn server_name_extension(name: &str) -> Vec<u8> {
        let entry = name.len() + 3;
        let mut extension = vec![0, 0];
        extension.extend_from_slice(&((entry + 2) as u16).to_be_bytes());
        extension.extend_from_slice(&(entry as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extension.extend_from_slice(name.as_bytes());
        extension
    }

    #[test]
    fn the_server_name_is_found_behind_other_extensions() {
        let mut extensions = vec![0, 0x17, 0, 0];
        extensions.extend(server_name_extension("api.github.com"));
        assert_eq!(
            server_name(&hello(&extensions)),
            Ok("api.github.com".to_string())
        );
    }

    #[test]
    fn a_hello_without_a_name_or_cut_short_is_refused() {
        assert_eq!(server_name(&hello(&[])), Err("no server_name"));
        assert_eq!(server_name(&[2, 0, 0, 0]), Err("not a client hello"));
        let cut = hello(&server_name_extension("x"));
        assert_eq!(server_name(&cut[..20]), Err("short hello"));
        assert_eq!(server_name(&hello(&[0, 0, 0xff, 0xff])), Err("short hello"));
        assert_eq!(
            server_name(&hello(&server_name_extension("x\nallow evil.test"))),
            Err("server_name is not a host name")
        );
    }

    #[test]
    fn a_wildcard_matches_subdomains_only() {
        let patterns = vec!["*.github.com".to_string(), "example.com".to_string()];
        assert!(allowed(&patterns, &[], "api.github.com"));
        assert!(allowed(&patterns, &[], "API.GitHub.com"));
        assert!(allowed(&patterns, &[], "example.com"));
        assert!(!allowed(&patterns, &[], "github.com"));
        assert!(!allowed(&patterns, &[], "evilgithub.com"));
        assert!(!allowed(&patterns, &[], "www.example.com"));
    }

    #[test]
    fn a_deny_pattern_wins_inside_a_grant() {
        let patterns = vec!["*.github.com".to_string()];
        let denied = vec![
            "gist.github.com".to_string(),
            "*.raw.github.com".to_string(),
        ];
        assert!(allowed(&patterns, &denied, "api.github.com"));
        assert!(!allowed(&patterns, &denied, "gist.github.com"));
        assert!(!allowed(&patterns, &denied, "GIST.github.com"));
        assert!(allowed(&patterns, &denied, "raw.github.com"));
        assert!(!allowed(&patterns, &denied, "x.raw.github.com"));
    }

    #[test]
    fn every_a_query_is_answered_with_the_bridge_address() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        thread::spawn(move || serve_dns(&server, Ipv4Addr::new(10, 30, 1, 1)));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        for (qtype, answers) in [(1u8, 1u8), (28, 0)] {
            let mut query = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            query.extend_from_slice(b"\x07example\x03com\x00");
            query.extend_from_slice(&[0, qtype, 0, 1]);
            // a query cut off after its type gets no answer and does not
            // end the resolver
            client.send_to(&query[..query.len() - 2], address).unwrap();
            client.send_to(&query, address).unwrap();
            let mut reply = [0u8; 512];
            let len = client.recv(&mut reply).unwrap();
            assert_eq!(&reply[..2], &[0xab, 0xcd]);
            assert_eq!(reply[7], answers);
            if answers == 1 {
                assert_eq!(&reply[len - 4..len], &[10, 30, 1, 1]);
            }
        }
    }
}
