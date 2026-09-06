//! the host end of a forward on firecracker's unix-socket vsock.
//! `serve <target>` takes a connection the guest opened, accepted by systemd
//! on `<uds>_<port>` and handed over as stdin, and splices it to a host
//! loopback port. `connect <uds> <port>` splices stdio to a guest port
//! through firecracker's CONNECT handshake.
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn connect(spec: &str) -> io::Result<Stream> {
        let port = spec
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid target port"))?;
        TcpStream::connect(("127.0.0.1", port)).map(Stream::Tcp)
    }

    fn try_clone(&self) -> io::Result<Stream> {
        match self {
            Stream::Tcp(stream) => stream.try_clone().map(Stream::Tcp),
            Stream::Unix(stream) => stream.try_clone().map(Stream::Unix),
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Stream::Unix(stream) => stream.shutdown(Shutdown::Write),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.read(buf),
            Stream::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.write(buf),
            Stream::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.flush(),
            Stream::Unix(stream) => stream.flush(),
        }
    }
}

fn splice(mut client: Stream, mut target: Stream) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut target_writer = target.try_clone()?;
    let target_to_client = thread::spawn(move || {
        let result = io::copy(&mut target, &mut client);
        let _ = client.shutdown_write();
        result
    });
    let client_to_target = io::copy(&mut client_reader, &mut target_writer);
    let _ = target_writer.shutdown_write();
    target_to_client
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))??;
    client_to_target?;
    Ok(())
}

fn serve(target: &str) -> io::Result<()> {
    let client = Stream::Unix(unsafe { UnixStream::from_raw_fd(0) });
    splice(client, Stream::connect(target)?)
}

/// stdio is a socket systemd accepted or a pipe from ssh; the guest side
/// closing ends the process, and stdin closing half-closes the guest side
fn connect(uds: &str, port: u16) -> io::Result<()> {
    let mut guest = UnixStream::connect(uds)?;
    guest.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut reply = String::new();
    BufReader::new(guest.try_clone()?).read_line(&mut reply)?;
    if !reply.starts_with("OK ") {
        return Err(io::Error::other(format!(
            "guest port {port}: {}",
            reply.trim()
        )));
    }
    let mut guest_writer = guest.try_clone()?;
    thread::spawn(move || {
        let mut stdin = unsafe { File::from_raw_fd(0) };
        let _ = io::copy(&mut stdin, &mut guest_writer);
        let _ = guest_writer.shutdown(Shutdown::Write);
    });
    let mut stdout = unsafe { File::from_raw_fd(1) };
    io::copy(&mut guest, &mut stdout)?;
    Ok(())
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fencr-vsock-forward serve <target-port> | connect <uds> <port>",
        )
    };
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve", target] => serve(target),
        ["connect", uds, port] => connect(uds, port.parse().map_err(|_| usage())?),
        _ => Err(usage()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fencr-vsock-forward: {error}");
            ExitCode::FAILURE
        }
    }
}
