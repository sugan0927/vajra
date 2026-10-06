//! Thin OS helpers: listener creation and CPU pinning.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;

/// Create a bound, listening TCP socket.
///
/// * `reuse_port`: set `SO_REUSEPORT` so every worker can bind its *own*
///   listener on the same address; the kernel then load-balances incoming
///   connections across them (no shared accept queue, no lock, no thundering
///   herd). This is the share-nothing way to scale accept().
/// * `TCP_NODELAY` is set on the listener: accepted sockets inherit it on
///   Linux, which saves one `setsockopt` syscall per connection.
pub fn listener(addr: SocketAddr, reuse_port: bool, backlog: i32) -> io::Result<Socket> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if reuse_port {
        sock.set_reuse_port(true)?;
    }
    sock.set_nodelay(true)?;
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    Ok(sock)
}

/// A bound, non-blocking UDP socket for QUIC (`SO_REUSEPORT` so each worker
/// owns one and the kernel spreads clients across them by 4-tuple).
pub fn udp_listener(addr: SocketAddr, reuse_port: bool) -> io::Result<Socket> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    if reuse_port {
        sock.set_reuse_port(true)?;
    }
    // Large buffers absorb bursts while the ring is busy (the kernel caps these at rmem_max/wmem_max).
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    sock.bind(&addr.into())?;
    Ok(sock)
}

/// Convert a kernel `sockaddr_storage` (as filled by `recvmsg`) to a `SocketAddr`.
pub fn sockaddr_to_std(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    // SAFETY: the family tag selects which sockaddr variant the kernel wrote.
    unsafe {
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                let a = &*(ss as *const _ as *const libc::sockaddr_in);
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                    u16::from_be(a.sin_port),
                )))
            }
            libc::AF_INET6 => {
                let a = &*(ss as *const _ as *const libc::sockaddr_in6);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(a.sin6_addr.s6_addr),
                    u16::from_be(a.sin6_port),
                    a.sin6_flowinfo,
                    a.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

/// Pin the *calling thread* to a single CPU.
pub fn pin_to_core(core: usize) -> io::Result<()> {
    // SAFETY: cpu_set_t is plain-old-data; zeroed is its valid empty state.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Number of CPUs this process may run on.
pub fn available_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Peer IP of a connected socket (one `getpeername` syscall).
pub fn peer_ip(fd: std::os::fd::RawFd) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    // SAFETY: sockaddr_storage is plain-old-data; the kernel fills at most `len` bytes.
    unsafe {
        let mut ss: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
            return None;
        }
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                let a = &*(&ss as *const _ as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let a = &*(&ss as *const _ as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

// ───────────────────────── signals ─────────────────────────

/// A process-level event delivered by a POSIX signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `SIGHUP`: reload the configuration.
    Reload,
    /// `SIGINT` / `SIGTERM`: shut down gracefully.
    Shutdown,
}

/// Block `SIGHUP`, `SIGINT` and `SIGTERM` in the calling thread.
///
/// Call this in `main` **before spawning any thread**: threads inherit the
/// mask, so the signals are delivered only to whoever calls [`wait_signal`].
/// Workers are therefore never interrupted by a signal handler.
pub fn block_signals() -> io::Result<()> {
    // SAFETY: sigset_t is plain-old-data; the libc calls only read/write it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
    }
    Ok(())
}

/// Block until one of the signals blocked by [`block_signals`] arrives.
pub fn wait_signal() -> Signal {
    // SAFETY: as above; `sigwait` writes the signal number into `sig`.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        loop {
            let mut sig: libc::c_int = 0;
            if libc::sigwait(&set, &mut sig) != 0 {
                continue;
            }
            return if sig == libc::SIGHUP { Signal::Reload } else { Signal::Shutdown };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_are_delivered_to_sigwait_not_handlers() {
        block_signals().unwrap();
        // SAFETY: raising a blocked signal to ourselves; it stays pending until sigwait.
        unsafe {
            libc::raise(libc::SIGHUP);
        }
        assert_eq!(wait_signal(), Signal::Reload);
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert_eq!(wait_signal(), Signal::Shutdown);
    }

    #[test]
    fn peer_ip_of_a_loopback_connection() {
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        assert_eq!(peer_ip(s.as_raw_fd()), Some("127.0.0.1".parse().unwrap()));
        drop(c);
    }
}
