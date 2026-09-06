use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

const AF_VSOCK: u16 = 40;

#[repr(C)]
struct SockaddrVm {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

unsafe extern "C" {
    fn getpeername(fd: RawFd, address: *mut SockaddrVm, length: *mut u32) -> i32;
}

fn peer_cid(fd: RawFd) -> io::Result<u32> {
    let mut address = SockaddrVm {
        family: 0,
        reserved: 0,
        port: 0,
        cid: 0,
        zero: [0; 4],
    };
    let mut length = std::mem::size_of::<SockaddrVm>() as u32;
    let result = unsafe { getpeername(fd, &mut address, &mut length) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if address.family != AF_VSOCK || length < std::mem::size_of::<SockaddrVm>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "accepted socket is not a vsock connection",
        ));
    }
    Ok(address.cid)
}

/// the host side of a forward: a loopback tcp port, or the credential
/// proxy's unix socket
enum Target {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Target {
    fn connect(spec: &str) -> io::Result<Target> {
        if let Some(path) = spec.strip_prefix("unix:") {
            return UnixStream::connect(path).map(Target::Unix);
        }
        let port = spec
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid target port"))?;
        TcpStream::connect(("127.0.0.1", port)).map(Target::Tcp)
    }

    fn try_clone(&self) -> io::Result<Target> {
        match self {
            Target::Tcp(stream) => stream.try_clone().map(Target::Tcp),
            Target::Unix(stream) => stream.try_clone().map(Target::Unix),
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Target::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Target::Unix(stream) => stream.shutdown(Shutdown::Write),
        }
    }
}

impl Read for Target {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Target::Tcp(stream) => stream.read(buf),
            Target::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for Target {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Target::Tcp(stream) => stream.write(buf),
            Target::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Target::Tcp(stream) => stream.flush(),
            Target::Unix(stream) => stream.flush(),
        }
    }
}

fn relay(mut client: TcpStream, mut target: Target) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut target_writer = target.try_clone()?;
    let target_to_client = thread::spawn(move || {
        let result = io::copy(&mut target, &mut client);
        let _ = client.shutdown(Shutdown::Write);
        result
    });
    let client_to_target = io::copy(&mut client_reader, &mut target_writer);
    let _ = target_writer.shutdown_write();
    let target_to_client = target_to_client
        .join()
        .map_err(|_| io::Error::other("vsock relay thread panicked"))?;
    client_to_target?;
    target_to_client?;
    Ok(())
}

fn run() -> io::Result<()> {
    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "agent-vsock-forward".to_owned());
    let usage = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("usage: {program} <peer-cid> <target-port|unix:<path>>"),
        )
    };
    let expected_cid = args
        .next()
        .ok_or_else(usage)?
        .parse::<u32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer cid"))?;
    let target_spec = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    if peer_cid(0)? != expected_cid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vsock peer is not the expected guest",
        ));
    }
    let client = unsafe { std::net::TcpStream::from_raw_fd(0) };
    let target = Target::connect(&target_spec)?;
    relay(client, target)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("agent-vsock-forward: {error}");
            ExitCode::FAILURE
        }
    }
}
