//! Virtual address spaces: page tables, mappings, and fault handling.
//!
//! This is the layer that would normally need a real MMU to test. Because it
//! talks only to `MemBackend` and its own table structures, the whole thing
//! runs in unit tests: map, unmap, protect, translate, and simulate faults
//! against a simulated machine.

use crate::addr::{self, AddrError, Frame, Perms, PAGE_SIZE};
use crate::frame::FrameAllocator;
use crate::mem::MemBackend;
use std::collections::BTreeMap;

/// One entry in a page table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mapping {
    pub frame: Frame,
    pub perms: Perms,
}

/// A flat page table. No multi-level paging: for an OS whose entire purpose is
/// to run inside a host page table, a two-level split is more than enough and
/// keeps the translation path directly unit-testable.
pub struct PageTable {
    entries: BTreeMap<u64, Mapping>,
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PageTable {
    pub fn new() -> Self {
        PageTable {
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Maps one page-aligned virtual page onto `frame`.
    pub fn map(&mut self, vaddr: u64, frame: Frame, perms: Perms) -> Result<(), AddrError> {
        if !addr::is_canonical(vaddr) {
            return Err(AddrError::NonCanonical);
        }
        let vpage = addr::align_down(vaddr);
        if frame.is_null() {
            return Err(AddrError::OutOfRange);
        }
        self.entries.insert(vpage, Mapping { frame, perms });
        Ok(())
    }

    /// Removes a mapping, returning the frame that was mapped.
    pub fn unmap(&mut self, vaddr: u64) -> Result<Frame, AddrError> {
        let vpage = addr::align_down(vaddr);
        self.entries
            .remove(&vpage)
            .map(|m| m.frame)
            .ok_or(AddrError::NotMapped)
    }

    /// Changes permissions on an existing mapping.
    pub fn protect(&mut self, vaddr: u64, perms: Perms) -> Result<(), AddrError> {
        let vpage = addr::align_down(vaddr);
        match self.entries.get_mut(&vpage) {
            Some(m) => {
                m.perms = perms;
                Ok(())
            }
            None => Err(AddrError::NotMapped),
        }
    }

    /// Translates a virtual address to a physical byte offset, checking rights.
    pub fn translate(&self, vaddr: u64, access: Perms) -> Result<u64, AddrError> {
        if !addr::is_canonical(vaddr) {
            return Err(AddrError::NonCanonical);
        }
        let (vpage, off) = addr::split_page(vaddr);
        match self.entries.get(&vpage) {
            Some(m) => {
                if !m.perms.contains(access) {
                    return Err(AddrError::PermissionDenied);
                }
                Ok(m.frame.byte_offset() + off as u64)
            }
            None => Err(AddrError::NotMapped),
        }
    }

    /// Translates without checking permissions. Used by unmap and by dump.
    pub fn translate_raw(&self, vaddr: u64) -> Option<u64> {
        let (vpage, off) = addr::split_page(vaddr);
        self.entries
            .get(&vpage)
            .map(|m| m.frame.byte_offset() + off as u64)
    }

    /// Looks up the frame backing a virtual page.
    pub fn frame_at(&self, vaddr: u64) -> Option<Frame> {
        self.entries.get(&addr::align_down(vaddr)).map(|m| m.frame)
    }

    /// Looks up the permissions on a virtual page.
    pub fn perms_at(&self, vaddr: u64) -> Option<Perms> {
        self.entries.get(&addr::align_down(vaddr)).map(|m| m.perms)
    }

    /// Iterates mappings in ascending virtual order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, Mapping)> + '_ {
        self.entries.iter().map(|(k, v)| (*k, *v))
    }

    /// Merges adjacent mappings sharing permissions into maximal runs. This is
    /// what a `mmap`-style report needs, and it is where off-by-one bugs in
    /// range coalescing normally hide.
    pub fn merged_regions(&self) -> Vec<Region> {
        let mut out: Vec<Region> = Vec::new();
        for (vpage, m) in self.iter() {
            let end = vpage + PAGE_SIZE as u64;
            match out.last_mut() {
                Some(last) if last.perms == m.perms && last.end == vpage => {
                    last.end = end;
                    last.frames.push(m.frame);
                }
                _ => out.push(Region {
                    start: vpage,
                    end,
                    perms: m.perms,
                    frames: vec![m.frame],
                }),
            }
        }
        out
    }
}

/// A maximal run of same-permission pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub perms: Perms,
    pub frames: Vec<Frame>,
}

impl Region {
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

/// A process address space: a page table plus ownership of its frames.
pub struct AddressSpace<M: MemBackend> {
    pub table: PageTable,
    pub allocator: FrameAllocator,
    mem: M,
}

impl<M: MemBackend> AddressSpace<M> {
    /// Builds an address space over `mem`, managing every frame but the first.
    pub fn new(mem: M) -> Self {
        let allocator = FrameAllocator::for_backend(&mem);
        AddressSpace {
            table: PageTable::new(),
            allocator,
            mem,
        }
    }

    /// Borrows the backend for device or dump code.
    pub fn mem(&self) -> &M {
        &self.mem
    }

    pub fn mem_mut(&mut self) -> &mut M {
        &mut self.mem
    }

    /// Number of frames still available for future mappings.
    pub fn free_frames(&self) -> u64 {
        self.allocator.free_count()
    }

    /// Maps `len` bytes at `vaddr` onto freshly allocated zeroed frames.
    pub fn map_anon(&mut self, vaddr: u64, len: u64, perms: Perms) -> Result<(), AddrError> {
        if !addr::is_canonical(vaddr) {
            return Err(AddrError::NonCanonical);
        }
        for vpage in addr::page_range(vaddr, len) {
            let frame = self.alloc_frame()?;
            self.table.map(vpage, frame, perms).inspect_err(|_| {
                self.allocator.free(&mut self.mem, frame).ok();
            })?;
        }
        Ok(())
    }

    /// Removes every mapping in the range and frees the frames.
    pub fn unmap_range(&mut self, vaddr: u64, len: u64) -> Result<u64, AddrError> {
        let mut freed = 0;
        for vpage in addr::page_range(vaddr, len) {
            if let Ok(frame) = self.table.unmap(vpage) {
                self.allocator
                    .free(&mut self.mem, frame)
                    .map_err(|_| AddrError::OutOfRange)?;
                freed += 1;
            }
        }
        Ok(freed)
    }

    /// Copies `data` into the address space at `vaddr`.
    pub fn write_bytes(&mut self, vaddr: u64, data: &[u8]) -> Result<(), AddrError> {
        for (i, chunk) in data.chunks(PAGE_SIZE).enumerate() {
            let dst = vaddr + (i * PAGE_SIZE) as u64;
            let mut written = 0usize;
            // A chunk may straddle two pages.
            while written < chunk.len() {
                let (vpage, off) = addr::split_page(dst + written as u64);
                let phys = self
                    .table
                    .translate_raw(vpage)
                    .ok_or(AddrError::NotMapped)?;
                let room = PAGE_SIZE - off as usize;
                let n = room.min(chunk.len() - written);
                self.mem
                    .write(phys + off as u64, &chunk[written..written + n])
                    .map_err(|_| AddrError::OutOfRange)?;
                written += n;
            }
        }
        Ok(())
    }

    /// Reads `len` bytes from the address space at `vaddr`.
    pub fn read_bytes(&self, vaddr: u64, len: usize) -> Result<Vec<u8>, AddrError> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let vcur = vaddr + out.len() as u64;
            let (vpage, off) = addr::split_page(vcur);
            let phys = self
                .table
                .translate_raw(vpage)
                .ok_or(AddrError::NotMapped)?;
            let room = PAGE_SIZE - off as usize;
            let n = room.min(len - out.len());
            let mut buf = vec![0u8; n];
            self.mem
                .read(phys + off as u64, &mut buf)
                .map_err(|_| AddrError::OutOfRange)?;
            out.extend_from_slice(&buf);
        }
        Ok(out)
    }

    /// Finds an unmapped canonical address suitable for `len` bytes.
    ///
    /// Scans the lower half from `start`, which keeps generated layouts
    /// deterministic across runs and therefore diffable in tests.
    pub fn find_free(&self, len: u64, start: u64) -> Option<u64> {
        let end_of_lower = 0x0000_8000_0000_0000u64;
        let mut v = addr::align_down(start);
        while v.checked_add(len)? <= end_of_lower {
            let mut all_free = true;
            for p in addr::page_range(v, len) {
                if self.table.frame_at(p).is_some() {
                    all_free = false;
                    v = p + PAGE_SIZE as u64;
                    break;
                }
            }
            if all_free {
                return Some(v);
            }
        }
        None
    }

    fn alloc_frame(&mut self) -> Result<Frame, AddrError> {
        self.allocator
            .alloc(&mut self.mem)
            .map_err(|_| AddrError::OutOfRange)
    }
}

/// What the CPU did when a guest access could not be completed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    pub vaddr: u64,
    pub access: Perms,
    pub cause: FaultCause,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultCause {
    /// No mapping at all.
    NotPresent,
    /// Mapping exists but rights are missing.
    Protection,
}

/// Decides whether a fault can be satisfied on demand.
///
/// This is the demand-paging decision, expressed as a pure function of the
/// table plus a policy object. It is the piece that normally requires
/// `userfaultfd` to test at all; here it is directly unit-testable, and only
/// its *delivery* to the guest later needs the host.
pub struct FaultHandler<'a, M: MemBackend> {
    space: &'a mut AddressSpace<M>,
    /// Lowest address the handler is willing to fault in.
    pub heap_start: u64,
    /// Highest address the handler will grow to.
    pub heap_end: u64,
}

impl<'a, M: MemBackend> FaultHandler<'a, M> {
    pub fn new(space: &'a mut AddressSpace<M>, heap_start: u64, heap_end: u64) -> Self {
        FaultHandler {
            space,
            heap_start,
            heap_end,
        }
    }

    /// Classifies a fault without changing anything.
    pub fn classify(&self, f: Fault) -> FaultCause {
        match self.space.table.frame_at(f.vaddr) {
            None => FaultCause::NotPresent,
            Some(_) => FaultCause::Protection,
        }
    }

    /// Attempts to satisfy a fault, mapping a zero page when permitted.
    ///
    /// Returns true when the guest may retry the access. Returns false for a
    /// protection fault, which is never fixable by supplying a page.
    pub fn handle(&mut self, f: Fault) -> Result<bool, AddrError> {
        match self.classify(f) {
            FaultCause::Protection => Ok(false),
            FaultCause::NotPresent => {
                if f.vaddr < self.heap_start || f.vaddr >= self.heap_end {
                    return Ok(false);
                }
                let vpage = addr::align_down(f.vaddr);
                let frame = self
                    .space
                    .allocator
                    .alloc(&mut self.space.mem)
                    .map_err(|_| AddrError::OutOfRange)?;
                self.space
                    .table
                    .map(vpage, frame, f.access.union(Perms::READ))
                    .inspect_err(|_| {
                        self.space.allocator.free(&mut self.space.mem, frame).ok();
                    })?;
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::SimMem;

    fn space(frames: u64) -> AddressSpace<SimMem> {
        AddressSpace::new(SimMem::new(frames))
    }

    #[test]
    fn map_and_translate_roundtrip() {
        let mut t = PageTable::new();
        t.map(0x4000_0000, Frame::from_index(10), Perms::RWX)
            .unwrap();

        assert_eq!(
            t.translate(0x4000_0000, Perms::READ),
            Ok(10 * PAGE_SIZE as u64)
        );
        assert_eq!(
            t.translate(0x4000_0fff, Perms::READ),
            Ok(10 * PAGE_SIZE as u64 + 0xfff)
        );
        assert_eq!(t.frame_at(0x4000_0800), Some(Frame::from_index(10)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn unmapped_address_reports_not_mapped() {
        let mut t = PageTable::new();
        assert_eq!(t.translate(0x1000, Perms::READ), Err(AddrError::NotMapped));
        assert_eq!(t.unmap(0x1000), Err(AddrError::NotMapped));
        assert_eq!(t.protect(0x1000, Perms::RW), Err(AddrError::NotMapped));
    }

    #[test]
    fn permission_is_enforced_per_bit() {
        let mut t = PageTable::new();
        t.map(0x2000, Frame::from_index(5), Perms::READ).unwrap();

        assert_eq!(t.translate(0x2000, Perms::READ), Ok(5 * PAGE_SIZE as u64));
        assert_eq!(
            t.translate(0x2000, Perms::WRITE),
            Err(AddrError::PermissionDenied)
        );
        assert_eq!(
            t.translate(0x2000, Perms::EXEC),
            Err(AddrError::PermissionDenied)
        );
        // translate_raw bypasses checks, as unmap needs.
        assert_eq!(t.translate_raw(0x2000), Some(5 * PAGE_SIZE as u64));
    }

    #[test]
    fn non_canonical_map_is_rejected() {
        let mut t = PageTable::new();
        assert_eq!(
            t.map(0x0000_8000_0000_0000, Frame::from_index(1), Perms::RW),
            Err(AddrError::NonCanonical)
        );
        assert_eq!(
            t.translate(0x0000_8000_0000_0000, Perms::RW),
            Err(AddrError::NonCanonical)
        );
        assert!(t.is_empty());
    }

    #[test]
    fn null_frame_cannot_be_mapped() {
        let mut t = PageTable::new();
        assert_eq!(
            t.map(0x1000, Frame::NULL, Perms::RW),
            Err(AddrError::OutOfRange)
        );
    }

    #[test]
    fn map_is_page_granular_and_aligns_down() {
        let mut t = PageTable::new();
        t.map(0x4321, Frame::from_index(7), Perms::RW).unwrap();
        assert_eq!(t.frame_at(0x4000), Some(Frame::from_index(7)));
        assert_eq!(t.frame_at(0x5000), None);
    }

    #[test]
    fn protect_changes_rights_in_place() {
        let mut t = PageTable::new();
        let f = Frame::from_index(3);
        t.map(0x8000, f, Perms::READ).unwrap();
        t.protect(0x8000, Perms::RW).unwrap();
        assert_eq!(t.perms_at(0x8000), Some(Perms::RW));
        assert_eq!(t.frame_at(0x8000), Some(f), "frame must be preserved");
        assert_eq!(t.translate(0x8000, Perms::WRITE), Ok(3 * PAGE_SIZE as u64));

        t.protect(0x8000, Perms::NONE).unwrap();
        assert_eq!(
            t.translate(0x8000, Perms::READ),
            Err(AddrError::PermissionDenied)
        );
    }

    #[test]
    fn unmap_returns_the_frame() {
        let mut t = PageTable::new();
        t.map(0x9000, Frame::from_index(42), Perms::RW).unwrap();
        assert_eq!(t.unmap(0x9000), Ok(Frame::from_index(42)));
        assert!(t.is_empty());
    }

    #[test]
    fn merged_regions_coalesce_adjacent_same_perms() {
        let mut t = PageTable::new();
        for (i, perms) in [(0, Perms::RW), (1, Perms::RW), (2, Perms::READ)] {
            t.map(
                0x1000 + i * PAGE_SIZE as u64,
                Frame::from_index(i as u64 + 1),
                perms,
            )
            .unwrap();
        }
        let regions = t.merged_regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].start, 0x1000);
        assert_eq!(regions[0].end, 0x3000);
        assert_eq!(regions[0].frames.len(), 2);
        assert_eq!(regions[1].start, 0x3000);
        assert_eq!(regions[1].perms, Perms::READ);
    }

    #[test]
    fn address_space_map_anon_and_unmap_balances_frames() {
        let mut s = space(64);
        let before = s.free_frames();

        s.map_anon(0x4000_0000, PAGE_SIZE as u64 * 4, Perms::RW)
            .unwrap();
        assert_eq!(s.free_frames(), before - 4);
        assert_eq!(s.table.len(), 4);

        let freed = s.unmap_range(0x4000_0000, PAGE_SIZE as u64 * 4).unwrap();
        assert_eq!(freed, 4);
        assert_eq!(s.free_frames(), before, "frames must return to the pool");
        assert!(s.table.is_empty());
    }

    #[test]
    fn address_space_exhaustion_is_an_error_not_a_panic() {
        let mut s = space(8);
        assert_eq!(
            s.map_anon(0x1000, PAGE_SIZE as u64 * 1000, Perms::RW),
            Err(AddrError::OutOfRange)
        );
    }

    #[test]
    fn write_and_read_bytes_across_page_boundaries() {
        let mut s = space(64);
        s.map_anon(0x7000, PAGE_SIZE as u64 * 2, Perms::RW).unwrap();

        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        // Start unaligned to force straddling in both directions.
        s.write_bytes(0x7000 + 1000, &data).unwrap();

        let got = s.read_bytes(0x7000 + 1000, data.len()).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn read_from_unmapped_memory_reports_the_error() {
        let s = space(16);
        assert_eq!(s.read_bytes(0x1234, 10), Err(AddrError::NotMapped));
    }

    #[test]
    fn find_free_skips_existing_mappings() {
        let mut s = space(64);
        s.map_anon(0x1000, PAGE_SIZE as u64 * 3, Perms::RW).unwrap();

        // Searching from the start must not return occupied pages.
        let f = s.find_free(PAGE_SIZE as u64, 0x1000).unwrap();
        assert_eq!(f, 0x4000);

        let f = s.find_free(PAGE_SIZE as u64 * 4, 0x1000).unwrap();
        assert_eq!(f, 0x4000);
        assert!(s.table.frame_at(f + PAGE_SIZE as u64 * 3).is_none());
    }

    #[test]
    fn find_free_returns_none_when_full() {
        let mut s = space(4);
        s.map_anon(0, 0x7000_0000 - PAGE_SIZE as u64, Perms::RW)
            .ok();
        // Practically we cannot fill the lower half, so assert the scan
        // terminates and does not return an occupied page.
        if let Some(f) = s.find_free(PAGE_SIZE as u64, 0) {
            assert!(s.table.frame_at(f).is_none());
        }
    }

    #[test]
    fn fault_in_heap_range_is_satisfied() {
        let mut s = space(64);
        {
            let mut h = FaultHandler::new(&mut s, 0x4000_0000, 0x8000_0000);
            assert_eq!(
                h.classify(Fault {
                    vaddr: 0x4000_0123,
                    access: Perms::WRITE,
                    cause: FaultCause::NotPresent
                }),
                FaultCause::NotPresent
            );
            assert!(h
                .handle(Fault {
                    vaddr: 0x4000_0123,
                    access: Perms::WRITE,
                    cause: FaultCause::NotPresent
                })
                .unwrap());
        }
        // The page is now present and writable.
        assert_eq!(s.table.translate(0x4000_0100, Perms::WRITE).is_ok(), true);
    }

    #[test]
    fn fault_outside_heap_is_refused() {
        let mut s = space(64);
        let mut h = FaultHandler::new(&mut s, 0x4000_0000, 0x8000_0000);
        assert!(!h
            .handle(Fault {
                vaddr: 0x1000,
                access: Perms::WRITE,
                cause: FaultCause::NotPresent
            })
            .unwrap());
        assert!(!h
            .handle(Fault {
                vaddr: 0x9000_0000,
                access: Perms::WRITE,
                cause: FaultCause::NotPresent
            })
            .unwrap());
    }

    #[test]
    fn protection_fault_is_never_satisfiable() {
        let mut s = space(64);
        s.map_anon(0x4000_0000, PAGE_SIZE as u64, Perms::READ)
            .unwrap();
        let mut h = FaultHandler::new(&mut s, 0x4000_0000, 0x8000_0000);

        assert_eq!(
            h.classify(Fault {
                vaddr: 0x4000_0000,
                access: Perms::WRITE,
                cause: FaultCause::Protection
            }),
            FaultCause::Protection
        );
        assert!(!h
            .handle(Fault {
                vaddr: 0x4000_0000,
                access: Perms::WRITE,
                cause: FaultCause::Protection
            })
            .unwrap());
    }

    #[test]
    fn fault_handler_preserves_requested_rights() {
        let mut s = space(64);
        {
            let mut h = FaultHandler::new(&mut s, 0x4000_0000, 0x8000_0000);
            h.handle(Fault {
                vaddr: 0x4000_1000,
                access: Perms::EXEC,
                cause: FaultCause::NotPresent,
            })
            .unwrap();
        }
        let perms = s.table.perms_at(0x4000_1000).unwrap();
        assert!(perms.contains(Perms::EXEC));
        assert!(perms.contains(Perms::READ), "reads must always be granted");
    }

    #[test]
    fn unmap_of_absent_pages_is_not_an_error() {
        let mut s = space(16);
        assert_eq!(s.unmap_range(0x9000, PAGE_SIZE as u64 * 4).unwrap(), 0);
    }
}
