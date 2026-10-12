//! Physical frame allocator: a bitmap over the frames a backend provides.
//!
//! Kept deliberately generic over `MemBackend` and independent of `Mutex`, so
//! tests can drive it deterministically and assert on exact frame indices.

use crate::addr::Frame;
use crate::mem::{MemBackend, MemError};

/// Failure modes of the allocator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// No free frame remains.
    OutOfMemory,
    /// The backend rejected the request.
    Backend(MemError),
    /// Freeing a frame that was never allocated.
    DoubleFree,
    /// Freeing a frame outside the managed range.
    OutOfRange,
}

/// Bitmap physical frame allocator.
///
/// Bit set means *free*, so a freshly allocated-and-zeroed buffer of the right
/// size is all that is needed to reach a deterministic initial state.
pub struct FrameAllocator {
    bitmap: Vec<u64>,
    base_frame: u64,
    frame_count: u64,
    free_count: u64,
}

impl FrameAllocator {
    /// Manages frames `[base, base + frame_count)`. Frame 0 is never managed.
    pub fn new(base_frame: u64, frame_count: u64) -> Self {
        let words = ((frame_count as usize) + 63) / 64;
        let mut bitmap = vec![u64::MAX; words];
        let remainder = (frame_count as usize) % 64;
        if remainder != 0 && !bitmap.is_empty() {
            let last = bitmap.len() - 1;
            bitmap[last] = (1u64 << remainder) - 1;
        }
        FrameAllocator {
            bitmap,
            base_frame,
            frame_count,
            free_count: frame_count,
        }
    }

    /// Builds an allocator sized to a backend, reserving frame 0.
    pub fn for_backend(backend: &dyn MemBackend) -> Self {
        let usable = backend.frame_count().saturating_sub(1);
        FrameAllocator::new(1, usable)
    }

    pub fn free_count(&self) -> u64 {
        self.free_count
    }

    pub fn total_count(&self) -> u64 {
        self.frame_count
    }

    /// Index within the managed range, or None if out of range.
    fn idx(&self, frame: Frame) -> Option<usize> {
        let rel = frame.index().checked_sub(self.base_frame)?;
        if rel >= self.frame_count {
            None
        } else {
            Some(rel as usize)
        }
    }

    #[inline]
    fn is_free(&self, i: usize) -> bool {
        self.bitmap[i / 64] & (1u64 << (i % 64)) != 0
    }

    #[inline]
    fn set_bit(&mut self, i: usize, value: bool) {
        let mask = 1u64 << (i % 64);
        if value {
            self.bitmap[i / 64] |= mask;
        } else {
            self.bitmap[i / 64] &= !mask;
        }
    }

    /// Allocates one zeroed frame.
    pub fn alloc(&mut self, backend: &mut dyn MemBackend) -> Result<Frame, FrameError> {
        for i in 0..self.frame_count as usize {
            if self.is_free(i) {
                let frame = Frame::from_index(self.base_frame + i as u64);
                self.set_bit(i, false);
                self.free_count -= 1;
                backend.mark_allocated(frame).map_err(FrameError::Backend)?;
                backend
                    .zero(frame.byte_offset(), crate::addr::PAGE_SIZE)
                    .map_err(FrameError::Backend)?;
                return Ok(frame);
            }
        }
        Err(FrameError::OutOfMemory)
    }

    /// Allocates `count` contiguous frames as one physical run.
    ///
    /// Contiguity matters for DMA and for single-frame device access, so this
    /// is a first-fit scan rather than a loop of `alloc`.
    pub fn alloc_contiguous(
        &mut self,
        backend: &mut dyn MemBackend,
        count: u64,
    ) -> Result<Frame, FrameError> {
        if count == 0 {
            return Ok(Frame::NULL);
        }
        if count > self.frame_count {
            return Err(FrameError::OutOfMemory);
        }
        let count = count as usize;
        let mut run = 0usize;
        for i in 0..self.frame_count as usize {
            if self.is_free(i) {
                run += 1;
                if run == count {
                    let start = i + 1 - count;
                    let base = Frame::from_index(self.base_frame + start as u64);
                    for k in start..=i {
                        self.set_bit(k, false);
                        backend
                            .mark_allocated(Frame::from_index(self.base_frame + k as u64))
                            .map_err(FrameError::Backend)?;
                    }
                    self.free_count -= count as u64;
                    backend
                        .zero(base.byte_offset(), count * crate::addr::PAGE_SIZE)
                        .map_err(FrameError::Backend)?;
                    return Ok(base);
                }
            } else {
                run = 0;
            }
        }
        Err(FrameError::OutOfMemory)
    }

    /// Returns a frame to the pool. Detects double frees.
    pub fn free(&mut self, backend: &mut dyn MemBackend, frame: Frame) -> Result<(), FrameError> {
        let i = self.idx(frame).ok_or(FrameError::OutOfRange)?;
        if self.is_free(i) {
            return Err(FrameError::DoubleFree);
        }
        self.set_bit(i, true);
        self.free_count += 1;
        backend.mark_free(frame).map_err(FrameError::Backend)
    }

    /// Releases a contiguous run previously returned by `alloc_contiguous`.
    pub fn free_contiguous(
        &mut self,
        backend: &mut dyn MemBackend,
        base: Frame,
        count: u64,
    ) -> Result<(), FrameError> {
        for k in 0..count {
            self.free(backend, Frame::from_index(base.index() + k))?;
        }
        Ok(())
    }

    /// True when `frame` is currently allocated.
    pub fn is_allocated(&self, frame: Frame) -> bool {
        match self.idx(frame) {
            Some(i) => !self.is_free(i),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::SimMem;

    #[test]
    fn allocates_frames_in_order_from_base() {
        let mut mem = SimMem::new(16);
        let mut a = FrameAllocator::new(1, 15);
        assert_eq!(a.total_count(), 15);
        assert_eq!(a.free_count(), 15);

        let f1 = a.alloc(&mut mem).unwrap();
        let f2 = a.alloc(&mut mem).unwrap();
        assert_eq!(f1.index(), 1);
        assert_eq!(f2.index(), 2);
        assert_eq!(a.free_count(), 13);
    }

    #[test]
    fn allocated_frames_are_zeroed() {
        let mut mem = SimMem::new(8);
        let mut a = FrameAllocator::new(1, 7);
        mem.write(Frame::from_index(3).byte_offset(), &[0xff; 64])
            .unwrap();

        let f = a.alloc(&mut mem).unwrap();
        assert!(mem.frame_slice(f).unwrap().iter().all(|b| *b == 0));
    }

    #[test]
    fn exhausting_the_pool_reports_oom_not_panic() {
        let mut mem = SimMem::new(5);
        let mut a = FrameAllocator::new(1, 4);
        for _ in 0..4 {
            a.alloc(&mut mem).unwrap();
        }
        assert_eq!(a.alloc(&mut mem), Err(FrameError::OutOfMemory));
        assert_eq!(a.free_count(), 0);
    }

    #[test]
    fn free_returns_frames_to_the_pool_and_is_reused() {
        let mut mem = SimMem::new(8);
        let mut a = FrameAllocator::new(1, 7);
        let f = a.alloc(&mut mem).unwrap();
        assert!(a.is_allocated(f));
        assert!(mem.is_allocated(f), "backend must record the allocation");

        a.free(&mut mem, f).unwrap();
        assert!(!a.is_allocated(f));
        assert!(!mem.is_allocated(f));
        assert_eq!(a.free_count(), 7);

        // The freed frame becomes the next allocation (first fit).
        assert_eq!(a.alloc(&mut mem).unwrap(), f);
    }

    #[test]
    fn double_free_is_detected() {
        let mut mem = SimMem::new(8);
        let mut a = FrameAllocator::new(1, 7);
        let f = a.alloc(&mut mem).unwrap();
        a.free(&mut mem, f).unwrap();
        assert_eq!(a.free(&mut mem, f), Err(FrameError::DoubleFree));
        // The failed free must not have corrupted the count.
        assert_eq!(a.free_count(), 7);
    }

    #[test]
    fn freeing_unmanaged_frames_is_rejected() {
        let mut mem = SimMem::new(8);
        let mut a = FrameAllocator::new(1, 7);
        assert_eq!(a.free(&mut mem, Frame::NULL), Err(FrameError::OutOfRange));
        assert_eq!(
            a.free(&mut mem, Frame::from_index(99)),
            Err(FrameError::OutOfRange)
        );
    }

    #[test]
    fn contiguous_allocation_finds_a_real_run() {
        let mut mem = SimMem::new(32);
        let mut a = FrameAllocator::new(1, 31);

        let base = a.alloc_contiguous(&mut mem, 4).unwrap();
        assert_eq!(base.index(), 1);
        for k in 0..4 {
            assert!(a.is_allocated(Frame::from_index(base.index() + k)));
        }
        assert_eq!(a.free_count(), 27);
    }

    #[test]
    fn contiguous_allocation_skips_a_fragmented_hole() {
        let mut mem = SimMem::new(32);
        let mut a = FrameAllocator::new(1, 31);

        // Carve out frames 2 and 3, leaving no 2-run starting at 1.
        let f1 = a.alloc(&mut mem).unwrap(); // 1
        let f2 = a.alloc(&mut mem).unwrap(); // 2
        let f3 = a.alloc(&mut mem).unwrap(); // 3
        a.free(&mut mem, f1).unwrap(); // 1 free, 2 and 3 busy

        let run = a.alloc_contiguous(&mut mem, 2).unwrap();
        assert_eq!(run.index(), 4, "should skip past the busy pair");

        a.free(&mut mem, f2).unwrap();
        a.free(&mut mem, f3).unwrap();
    }

    #[test]
    fn contiguous_allocation_fails_when_no_run_fits() {
        let mut mem = SimMem::new(16);
        let mut a = FrameAllocator::new(1, 15);
        // Allocate every other frame, destroying all 2-runs.
        let mut held = Vec::new();
        for _ in 0..7 {
            held.push(a.alloc(&mut mem).unwrap());
            a.alloc(&mut mem).unwrap();
        }
        assert_eq!(
            a.alloc_contiguous(&mut mem, 2),
            Err(FrameError::OutOfMemory)
        );
        for f in held {
            a.free(&mut mem, f).unwrap();
        }
    }

    #[test]
    fn zero_and_oversized_contiguous_requests() {
        let mut mem = SimMem::new(8);
        let mut a = FrameAllocator::new(1, 7);
        assert_eq!(a.alloc_contiguous(&mut mem, 0).unwrap(), Frame::NULL);
        assert_eq!(
            a.alloc_contiguous(&mut mem, 8),
            Err(FrameError::OutOfMemory)
        );
    }

    #[test]
    fn for_backend_reserves_frame_zero() {
        let mem = SimMem::new(64);
        let a = FrameAllocator::for_backend(&mem);
        assert_eq!(a.base_frame, 1);
        assert_eq!(a.total_count(), 63);
    }

    #[test]
    fn non_word_sized_pool_masks_the_excess_bits() {
        // A pool of 3 frames must hand out exactly 3 frames, never 4.
        let mut mem = SimMem::new(8);
        let mut a = FrameAllocator::new(1, 3);
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(a.alloc(&mut mem).unwrap().index());
        }
        assert_eq!(got, vec![1, 2, 3]);
        assert_eq!(a.alloc(&mut mem), Err(FrameError::OutOfMemory));
    }

    #[test]
    fn stress_random_alloc_free_keeps_the_count_consistent() {
        // Deterministic LCG so failures reproduce exactly.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let mut mem = SimMem::new(300);
        let mut a = FrameAllocator::new(1, 299);
        let mut held: Vec<Frame> = Vec::new();

        for _ in 0..20_000 {
            if held.is_empty() || (rand() % 3) != 0 {
                if let Ok(f) = a.alloc(&mut mem) {
                    held.push(f);
                }
            } else {
                let i = (rand() % held.len() as u64) as usize;
                let f = held.swap_remove(i);
                a.free(&mut mem, f).unwrap();
            }
            assert_eq!(
                a.free_count(),
                a.total_count() - held.len() as u64,
                "accounting drifted"
            );
        }
        for f in held {
            a.free(&mut mem, f).unwrap();
        }
        assert_eq!(a.free_count(), a.total_count());
    }
}
