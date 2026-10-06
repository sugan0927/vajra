//! Per-core slab allocator for fixed-size connection buffers.
//!
//! One anonymous `mmap` region is carved into equal, 64-byte-aligned slots
//! (a multiple of the cache-line size, so two connections never share a line).
//! Allocation is a pop from a recycle stack or a bump of a cursor: O(1), no
//! locks, no atomics, no `malloc` metadata, and neighbouring connections'
//! buffers are contiguous in memory.
//!
//! The mapping is created with `MAP_NORESERVE` and is never pre-faulted, so a
//! 64k-connection capacity costs virtual address space only; physical pages are
//! committed as slots are first touched.
//!
//! The pool is deliberately `!Send`/`!Sync` (raw pointers inside): it belongs
//! to exactly one worker thread. Having one contiguous region also lets a later
//! phase register it with `IORING_REGISTER_BUFFERS` in a single call.

use std::io;
use std::ptr::{self, NonNull};

const CACHE_LINE: usize = 64;

/// A fixed-size buffer living inside a [`SlabPool`] region.
pub struct PoolBuf {
    ptr: NonNull<u8>,
    len: usize,
    idx: u32,
}

impl PoolBuf {
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr..ptr+len is inside the live mapping owned by the pool
        // and zero-initialised by the kernel; the &self borrow prevents aliasing.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, with exclusive access through &mut self.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

pub struct SlabPool {
    base: *mut u8,
    map_len: usize,
    slot_size: usize,
    capacity: usize,
    next_fresh: u32,
    recycled: Vec<u32>,
}

impl SlabPool {
    /// Reserve room for `capacity` slots of at least `slot_size` bytes
    /// (rounded up to a multiple of 64).
    pub fn new(slot_size: usize, capacity: usize) -> io::Result<Self> {
        if slot_size == 0 || capacity == 0 || capacity > u32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad slab geometry"));
        }
        let slot_size = slot_size.div_ceil(CACHE_LINE) * CACHE_LINE;
        let map_len = slot_size
            .checked_mul(capacity)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "slab too large"))?;

        // SAFETY: anonymous private mapping; no fd, no aliasing.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            base: p as *mut u8,
            map_len,
            slot_size,
            capacity,
            next_fresh: 0,
            recycled: Vec::new(),
        })
    }

    /// Size of every slot (after rounding).
    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    /// Take a slot, or `None` when the pool is exhausted.
    pub fn alloc(&mut self) -> Option<PoolBuf> {
        let idx = if let Some(i) = self.recycled.pop() {
            i
        } else if (self.next_fresh as usize) < self.capacity {
            let i = self.next_fresh;
            self.next_fresh += 1;
            i
        } else {
            return None;
        };
        // SAFETY: idx < capacity, so the offset stays inside the mapping.
        let p = unsafe { self.base.add(idx as usize * self.slot_size) };
        Some(PoolBuf { ptr: NonNull::new(p)?, len: self.slot_size, idx })
    }

    /// Return a slot for reuse. Contents are left as-is (not zeroed).
    pub fn free(&mut self, buf: PoolBuf) {
        self.recycled.push(buf.idx);
    }
}

impl Drop for SlabPool {
    fn drop(&mut self) {
        // SAFETY: base/map_len came from a successful mmap in `new`.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.map_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_aligned_and_rounded() {
        let mut p = SlabPool::new(100, 4).unwrap();
        assert_eq!(p.slot_size(), 128);
        let mut a = p.alloc().unwrap();
        let mut b = p.alloc().unwrap();
        assert_eq!(a.len(), 128);
        assert_eq!(a.as_mut_ptr() as usize % 64, 0);
        assert_eq!(b.as_mut_ptr() as usize % 64, 0);
        assert_eq!(b.as_mut_ptr() as usize - a.as_mut_ptr() as usize, 128);
    }

    #[test]
    fn slots_do_not_overlap() {
        let mut p = SlabPool::new(64, 3).unwrap();
        let mut a = p.alloc().unwrap();
        let mut b = p.alloc().unwrap();
        a.as_mut_slice().fill(0xAA);
        b.as_mut_slice().fill(0xBB);
        assert!(a.as_slice().iter().all(|&x| x == 0xAA));
        assert!(b.as_slice().iter().all(|&x| x == 0xBB));
    }

    #[test]
    fn exhaustion_and_recycling() {
        let mut p = SlabPool::new(64, 2).unwrap();
        let a = p.alloc().unwrap();
        let _b = p.alloc().unwrap();
        assert!(p.alloc().is_none());
        p.free(a);
        assert!(p.alloc().is_some());
        assert!(p.alloc().is_none());
    }

    #[test]
    fn rejects_bad_geometry() {
        assert!(SlabPool::new(0, 4).is_err());
        assert!(SlabPool::new(64, 0).is_err());
    }
}
