//! Cross-core control plane: lock-free message passing into a worker's event loop.
//!
//! The data path shares nothing. Anything that must reach a worker from the
//! outside (metrics scrapes, config reloads, shutdown) travels as a [`Cmd`]
//! over a `std::sync::mpsc` channel (lock-free in the standard library) and
//! wakes the worker through an `eventfd` that the worker waits on with an
//! `IORING_OP_READ`. Workers never block on or poll the channel; the ring
//! tells them when there is mail.
//!
//! Replies go back over one-shot channels carried inside the command.

use crate::cache::CacheStats;
use crate::config::Dynamic;
use crate::observe::Metrics;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

/// A worker's counters at one instant.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub worker: usize,
    pub metrics: Metrics,
    pub active_conns: usize,
    pub cache: CacheStats,
    pub cache_entries: usize,
    pub cache_bytes: usize,
}

pub enum Cmd {
    /// Send back a [`Snapshot`].
    Scrape(Sender<Snapshot>),
    /// Swap the reloadable configuration. The worker validates and builds
    /// everything first, then swaps, so a bad config leaves it untouched.
    Reload { dynamic: Arc<Dynamic>, ack: Sender<Result<(), String>> },
    /// Stop accepting, finish in-flight work, exit after the grace period.
    Shutdown,
}

/// Sending side (cloneable, usable from any thread).
#[derive(Clone)]
pub struct Handle {
    tx: Sender<Cmd>,
    efd: Arc<OwnedFd>,
}

/// Receiving side, owned by the worker.
pub struct Inbox {
    rx: Receiver<Cmd>,
    efd: Arc<OwnedFd>,
}

pub fn channel() -> io::Result<(Handle, Inbox)> {
    // SAFETY: plain syscall; the returned fd is owned from here on.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid descriptor we exclusively own.
    let efd = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
    let (tx, rx) = mpsc::channel();
    Ok((Handle { tx, efd: Arc::clone(&efd) }, Inbox { rx, efd }))
}

impl Handle {
    /// Queue a command and wake the worker. `false` if the worker is gone.
    pub fn send(&self, cmd: Cmd) -> bool {
        if self.tx.send(cmd).is_err() {
            return false;
        }
        let one: u64 = 1;
        // SAFETY: writing 8 bytes from a live u64 to an eventfd we own.
        unsafe {
            libc::write(self.efd.as_raw_fd(), &one as *const u64 as *const libc::c_void, 8);
        }
        true
    }
}

impl Inbox {
    /// The eventfd the worker waits on.
    pub fn fd(&self) -> RawFd {
        self.efd.as_raw_fd()
    }

    pub fn try_recv(&self) -> Option<Cmd> {
        self.rx.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_efd(fd: RawFd) -> u64 {
        let mut v: u64 = 0;
        // SAFETY: reading 8 bytes into a live u64 from a valid eventfd.
        let n = unsafe { libc::read(fd, &mut v as *mut u64 as *mut libc::c_void, 8) };
        assert_eq!(n, 8);
        v
    }

    #[test]
    fn send_wakes_and_delivers_in_order() {
        let (h, inbox) = channel().unwrap();
        assert!(h.send(Cmd::Shutdown));
        let (tx, _rx) = mpsc::channel();
        assert!(h.clone().send(Cmd::Scrape(tx)));
        assert_eq!(read_efd(inbox.fd()), 2, "two wakeups accumulated");
        assert!(matches!(inbox.try_recv(), Some(Cmd::Shutdown)));
        assert!(matches!(inbox.try_recv(), Some(Cmd::Scrape(_))));
        assert!(inbox.try_recv().is_none());
    }

    #[test]
    fn send_to_dropped_worker_reports_failure() {
        let (h, inbox) = channel().unwrap();
        drop(inbox);
        assert!(!h.send(Cmd::Shutdown));
    }

    #[test]
    fn reply_channels_work_across_threads() {
        let (h, inbox) = channel().unwrap();
        let t = std::thread::spawn(move || {
            read_efd(inbox.fd());
            if let Some(Cmd::Reload { ack, .. }) = inbox.try_recv() {
                ack.send(Err("nope".into())).unwrap();
            }
        });
        let (ack, rx) = mpsc::channel();
        assert!(h.send(Cmd::Reload { dynamic: Arc::new(Dynamic::default()), ack }));
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(), Err("nope".to_string()));
        t.join().unwrap();
    }
}
