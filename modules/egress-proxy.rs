//! the road out for a vm with allowedDomains: on the bridge address it
//! answers every dns name with itself and, on 443, reads the server name
//! from the tls client hello, checks it against the allowlist and splices
//! the connection to the real host unread. nothing is decrypted.
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// `*.example.com` matches any name ending in `.example.com`; anything
/// else matches itself, case-insensitively
fn allowed(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    patterns
        .iter()
        .any(|pattern| match pattern.strip_prefix("*.") {
            Some(suffix) => {
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            None => host == *pattern,
        })
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
        extensions -= 4 + length;
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
        return std::str::from_utf8(name)
            .map(str::to_owned)
            .map_err(|_| "server_name is not utf-8");
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

fn splice(mut client: TcpStream, mut server: TcpStream) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut server_writer = server.try_clone()?;
    let server_to_client = thread::spawn(move || {
        let result = io::copy(&mut server, &mut client);
        let _ = client.shutdown(Shutdown::Write);
        result
    });
    let client_to_server = io::copy(&mut client_reader, &mut server_writer);
    let _ = server_writer.shutdown(Shutdown::Write);
    server_to_client
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))??;
    client_to_server?;
    Ok(())
}

fn serve_tls(mut client: TcpStream, patterns: &[String]) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (hello, name) = read_client_hello(&mut client)?;
    let host = match name {
        Ok(host) => host,
        Err(reason) => {
            eprintln!("deny: {reason}");
            return Ok(());
        }
    };
    if !allowed(patterns, &host) {
        eprintln!("deny {host}");
        return Ok(());
    }
    // the unit's IPAddressDeny is what keeps an allowed name out of the lan
    let address = (host.as_str(), 443u16)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| io::Error::other(format!("{host} has no ipv4 address")))?;
    let mut server = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    client.set_read_timeout(None)?;
    eprintln!("allow {host}");
    server.write_all(&hello)?;
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
        let Some(qtype) = query.get(at..at + 2) else {
            continue;
        };
        let question = &query[12..at + 4];
        let mut reply = Vec::with_capacity(len + 16);
        reply.extend_from_slice(&query[0..2]);
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
        reply.extend_from_slice(question);
        if qtype == [0, 1] {
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            reply.extend_from_slice(&answer.octets());
        }
        let _ = socket.send_to(&reply, peer);
    }
}

fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(address), Some(allowlist)) = (args.next(), args.next()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fencr-egress-proxy <bridge address> <allowlist file>",
        ));
    };
    let answer: Ipv4Addr = address
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bridge address must be ipv4"))?;
    let patterns: Arc<Vec<String>> = Arc::new(
        std::fs::read_to_string(allowlist)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect(),
    );
    // the bridge gets its address from networkd; be there when it does
    let dns = loop {
        match UdpSocket::bind((IpAddr::V4(answer), 53)) {
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
    let listener = TcpListener::bind((IpAddr::V4(answer), 443))?;
    for client in listener.incoming() {
        let client = client?;
        let patterns = Arc::clone(&patterns);
        thread::spawn(move || {
            if let Err(error) = serve_tls(client, &patterns) {
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
