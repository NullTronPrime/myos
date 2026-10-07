//! Physical memory abstraction and a pure-Rust simulator for it.
//!
//! `MemBackend` is the seam that makes the rest of the kernel testable. The
//! real implementation in `osplat` mmaps host memory; the simulator here is a
//! `Vec<u8>` that pretends to be RAM. Every layer above this trait is
//! exercised against the simulator in unit tests, so paging bugs surface as
//! assertion failures rather than as crashes inside a booted kernel.

use crate::addr::{Frame, PAGE_SIZE};
use std::collections::BTreeMap;

/// Errors a memory backend can report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemError {
    /// The frame index is past the end of physical memory.
    OutOfRange,
    /// The frame exists but has not been allocated to a consumer.
    Unallocated,
    /// A read or write ran off the end of the requested buffer.
    Bounds,
}

/// Read/write access to flat physical memory.
pub trait MemBackend {
    /// Total number of addressable frames.
    fn frame_count(&self) -> u64;

    /// Copies `len` bytes starting at byte offset `phys_off` into `buf`.
    fn read(&self, phys_off: u64, buf: &mut [u8]) -> Result<(), MemError>;

    /// Copies `buf` to byte offset `phys_off`.
    fn write(&mut self, phys_off: u64, buf: &[u8]) -> Result<(), MemError>;

    /// Zeroes `len` bytes at `phys_off`.
    fn zero(&mut self, phys_off: u64, len: usize) -> Result<(), MemError>;

    /// Raw access to a single frame. Returns an error for unallocated frames.
    fn frame_slice(&mut self, frame: Frame) -> Result<&mut [u8], MemError> {
        if frame.is_null() {
            return Err(MemError::Unallocated);
        }
        if frame.index() >= self.frame_count() {
            return Err(MemError::OutOfRange);
        }
        let off = frame.byte_offset();
        if (off as usize) + PAGE_SIZE > self.data_len() {
            return Err(MemError::OutOfRange);
        }
        let s = (off as usize)..(off as usize) + PAGE_SIZE;
        Ok(&mut self.data_mut()[s])
    }

    /// Length of the underlying backing store in bytes. Provided by impls.
    fn data_len(&self) -> usize;

    /// Mutable view of the entire backing store.
    fn data_mut(&mut self) -> &mut [u8];

    /// Number of bytes of real backing store available.
    fn byte_len(&self) -> usize {
        (self.frame_count() * PAGE_SIZE as u64) as usize
    }

    /// Marks a frame as handed out. Backends that track allocation state
    /// implement this; the simulator records it so double-free is detectable.
    fn mark_allocated(&mut self, _frame: Frame) -> Result<(), MemError> {
        Ok(())
    }

    /// Releases a frame's allocation.
    fn mark_free(&mut self, _frame: Frame) -> Result<(), MemError> {
        Ok(())
    }
}

/// A simulated physical memory backed by a byte vector.
///
/// Frames are tracked individually so that the simulator can distinguish
/// "this frame was never allocated" from "this frame holds zeroes", which is
/// what lets allocator tests assert on leaks and double frees.
pub struct SimMem {
    data: Vec<u8>,
    frames: u64,
    allocated: BTreeMap<u64, bool>,
}

impl SimMem {
    /// Creates a simulator with `frames` frames of 4 KiB each.
    pub fn new(frames: u64) -> Self {
        let bytes = (frames * PAGE_SIZE as u64) as usize;
        SimMem {
            data: vec![0u8; bytes],
            frames,
            allocated: BTreeMap::new(),
        }
    }

    /// Number of frames currently marked allocated.
    pub fn allocated_count(&self) -> u64 {
        self.allocated.values().filter(|v| **v).count() as u64
    }

    /// True when `frame` is currently marked allocated.
    pub fn is_allocated(&self, frame: Frame) -> bool {
        self.allocated.get(&frame.index()).copied().unwrap_or(false)
    }

    /// Raw access to the backing bytes. Test-only convenience.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl MemBackend for SimMem {
    fn frame_count(&self) -> u64 {
        self.frames
    }

    fn read(&self, phys_off: u64, buf: &mut [u8]) -> Result<(), MemError> {
        let start = phys_off as usize;
        if start > self.data.len() {
            return Err(MemError::OutOfRange);
        }
        let end = start.checked_add(buf.len()).ok_or(MemError::Bounds)?;
        if end > self.data.len() {
            return Err(MemError::OutOfRange);
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }

    fn write(&mut self, phys_off: u64, buf: &[u8]) -> Result<(), MemError> {
        let start = phys_off as usize;
        if start > self.data.len() {
            return Err(MemError::OutOfRange);
        }
        let end = start.checked_add(buf.len()).ok_or(MemError::Bounds)?;
        if end > self.data.len() {
            return Err(MemError::OutOfRange);
        }
        self.data[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn zero(&mut self, phys_off: u64, len: usize) -> Result<(), MemError> {
        let start = phys_off as usize;
        if start > self.data.len() {
            return Err(MemError::OutOfRange);
        }
        let end = start.checked_add(len).ok_or(MemError::Bounds)?;
        if end > self.data.len() {
            return Err(MemError::OutOfRange);
        }
        for b in &mut self.data[start..end] {
            *b = 0;
        }
        Ok(())
    }

    fn data_len(&self) -> usize {
        self.data.len()
    }

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn mark_allocated(&mut self, frame: Frame) -> Result<(), MemError> {
        if frame.index() == 0 || frame.index() >= self.frames {
            return Err(MemError::OutOfRange);
        }
        self.allocated.insert(frame.index(), true);
        Ok(())
    }

    fn mark_free(&mut self, frame: Frame) -> Result<(), MemError> {
        self.allocated.insert(frame.index(), false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip_across_frame_boundaries() {
        let mut mem = SimMem::new(4);
        let pattern: Vec<u8> = (0..=255u8).cycle().take(4000).collect();

        // Deliberately straddle a page boundary in both directions.
        let off = PAGE_SIZE as u64 * 2 - 100;
        mem.write(off, &pattern).unwrap();

        let mut got = vec![0u8; pattern.len()];
        mem.read(off, &mut got).unwrap();
        assert_eq!(got, pattern);
    }

    #[test]
    fn a_full_memory_writes_and_reads_without_error() {
        let mut mem = SimMem::new(2);
        let len = mem.byte_len();
        let pattern = vec![0x5au8; len];
        assert_eq!(mem.write(0, &pattern), Ok(()));
        let mut got = vec![0u8; len];
        assert_eq!(mem.read(0, &mut got), Ok(()));
        assert_eq!(got, pattern);
    }

    #[test]
    fn out_of_range_access_is_rejected_not_panicked() {
        let mut mem = SimMem::new(2);
        let mut buf = [0u8; 16];
        let end = 2 * PAGE_SIZE as u64;
        assert_eq!(mem.read(end - 4, &mut buf), Err(MemError::OutOfRange));
        assert_eq!(mem.write(end - 4, &buf), Err(MemError::OutOfRange));
        // An offset beyond any possible allocation cannot overflow the
        // bounds check, so it must still be OutOfRange, not Bounds.
        assert_eq!(mem.zero(u64::MAX, 4), Err(MemError::OutOfRange));
        assert_eq!(mem.write(u64::MAX, &buf), Err(MemError::OutOfRange));
    }

    #[test]
    fn lengths_are_bounded_by_the_store_not_by_intuition() {
        // A request that starts inside the store but runs past its end must be
        // rejected rather than truncating, which is what makes the read/write
        // pair safe to use for DMA-style copies.
        let mut mem = SimMem::new(2);
        let len = mem.byte_len() as u64;
        let mut buf = vec![0u8; len as usize];
        assert_eq!(mem.read(len - 1, &mut buf), Err(MemError::OutOfRange));
        assert_eq!(mem.write(len - 1, &buf), Err(MemError::OutOfRange));
        // Exactly the store size is fine.
        let mut exact = vec![0u8; len as usize];
        assert_eq!(mem.read(0, &mut exact), Ok(()));
    }

    #[test]
    fn allocation_state_is_tracked_independently_of_contents() {
        let mut mem = SimMem::new(8);
        let f = Frame::from_index(3);
        assert!(!mem.is_allocated(f));

        mem.mark_allocated(f).unwrap();
        assert!(mem.is_allocated(f));
        assert_eq!(mem.allocated_count(), 1);
        // Contents are still zero, so a zeroed frame and an unallocated frame
        // are genuinely distinguishable.
        assert!(mem.frame_slice(f).unwrap().iter().all(|b| *b == 0));

        mem.mark_free(f).unwrap();
        assert!(!mem.is_allocated(f));
        assert_eq!(mem.allocated_count(), 0);
    }

    #[test]
    fn reserved_and_oob_frames_are_not_allocatable() {
        let mut mem = SimMem::new(4);
        assert_eq!(mem.mark_allocated(Frame::NULL), Err(MemError::OutOfRange));
        assert_eq!(
            mem.mark_allocated(Frame::from_index(4)),
            Err(MemError::OutOfRange)
        );
    }

    #[test]
    fn zero_clears_only_the_requested_range() {
        let mut mem = SimMem::new(2);
        mem.write(0, &[0xaa; PAGE_SIZE]).unwrap();
        mem.zero(10, 5).unwrap();
        assert!(mem.bytes()[10..15].iter().all(|b| *b == 0));
        assert!(mem.bytes()[15..PAGE_SIZE].iter().all(|b| *b == 0xaa));
        assert_eq!(
            mem.bytes()[PAGE_SIZE..PAGE_SIZE + 10]
                .iter()
                .all(|b| *b == 0),
            true
        );
    }

    #[test]
    fn frame_slice_is_exactly_one_page() {
        let mut mem = SimMem::new(3);
        let f = Frame::from_index(2);
        let s = mem.frame_slice(f).unwrap();
        assert_eq!(s.len(), PAGE_SIZE);
    }
}
