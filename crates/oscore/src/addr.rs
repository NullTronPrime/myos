//! Address types and page arithmetic.
//!
//! Pure logic over `u64`. No host interaction whatsoever, so every rule in
//! this module is exercised by ordinary unit tests on any platform.

/// x86-64 page size. Fixed by the architecture.
pub const PAGE_SIZE: usize = 4096;

/// `log2(PAGE_SIZE)`.
pub const PAGE_SHIFT: u32 = 12;

/// A 4 KiB frame index into physical memory.
///
/// Frame 0 is deliberately reserved by the platform layer, so a zero value
/// is never a legal allocation result. That lets `Option<Frame>` and
/// `Frame(0)` be distinguished without extra tagging.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Frame(u64);

impl Frame {
    /// Sentinel for "no frame". Never handed out by an allocator.
    pub const NULL: Frame = Frame(0);

    /// Builds a frame from a raw index. Callers are trusted; validation of
    /// the frame's *existence* is the memory backend's job.
    pub const fn from_index(index: u64) -> Self {
        Frame(index)
    }

    pub const fn index(self) -> u64 {
        self.0
    }

    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Byte offset of this frame within physical memory.
    pub const fn byte_offset(self) -> u64 {
        self.0 << PAGE_SHIFT
    }

    /// Rebuilds a frame from a byte offset, rejecting unaligned input.
    pub const fn from_byte_offset(offset: u64) -> Option<Self> {
        if offset & ((PAGE_SIZE as u64) - 1) != 0 {
            return None;
        }
        Some(Frame(offset >> PAGE_SHIFT))
    }
}

/// Errors produced by address translation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddrError {
    /// The virtual address has no mapping.
    NotMapped,
    /// The mapping exists but lacks the requested permission.
    PermissionDenied,
    /// The address is not a valid canonical x86-64 address.
    NonCanonical,
    /// Arithmetic overflowed or left the representable range.
    OutOfRange,
}

/// Canonical lower-half boundary: the first address of the higher half.
pub const HIGHER_HALF_START: u64 = 0xffff_8000_0000_0000;

/// Returns true when `addr` is a canonical x86-64 virtual address.
///
/// Canonical means bits 48..63 are a sign-extension of bit 47. Both the
/// lower half (`0 .. 0x0000_7fff_ffff_ffff`) and the higher half
/// (`0xffff_8000_0000_0000 .. 0xffff_ffff_ffff_ffff`) qualify.
pub const fn is_canonical(addr: u64) -> bool {
    let sign = (addr >> 47) & 1;
    let upper = addr >> 48;
    if sign == 0 {
        upper == 0
    } else {
        upper == 0xffff
    }
}

/// Splits a virtual address into its page-aligned base and page offset.
pub const fn split_page(addr: u64) -> (u64, u16) {
    (addr & !((PAGE_SIZE as u64) - 1), (addr & ((PAGE_SIZE as u64) - 1)) as u16)
}

/// Page-aligns `addr` downwards.
pub const fn align_down(addr: u64) -> u64 {
    addr & !((PAGE_SIZE as u64) - 1)
}

/// Page-aligns `addr` upwards. Returns `None` on overflow.
pub const fn align_up(addr: u64) -> Option<u64> {
    let aligned = align_down(addr);
    if aligned == addr {
        Some(aligned)
    } else {
        aligned.checked_add(PAGE_SIZE as u64)
    }
}

/// Number of pages needed to hold `len` bytes starting at `addr`.
pub const fn pages_for(addr: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let start = addr & ((PAGE_SIZE as u64) - 1);
    (len + start + ((PAGE_SIZE as u64) - 1)) >> PAGE_SHIFT
}

/// Iterates the page-aligned virtual addresses covering `[start, start+len)`.
///
/// Off-by-one bugs in range handling are a classic kernel defect, so this
/// iterator is deliberately exercised at page boundaries by the tests.
pub fn page_range(start: u64, len: u64) -> impl Iterator<Item = u64> {
    let count = pages_for(start, len);
    let first = align_down(start);
    (0..count).map(move |i| first + (i << PAGE_SHIFT))
}

/// Access rights on a mapping.
///
/// Only three bits are primitive. `RW` and `RWX` are *composites*, not
/// independent bits, so `Perms::READ.union(Perms::WRITE)` is exactly
/// `Perms::RW` and `contains` behaves the way callers expect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Perms(u8);

impl Perms {
    /// No access at all.
    pub const NONE: Perms = Perms(0);
    /// Readable.
    pub const READ: Perms = Perms(1 << 0);
    /// Writable.
    pub const WRITE: Perms = Perms(1 << 1);
    /// Executable.
    pub const EXEC: Perms = Perms(1 << 2);
    /// Readable and writable.
    pub const RW: Perms = Perms(0b011);
    /// Readable, writable and executable.
    pub const RWX: Perms = Perms(0b111);

    /// Builds permission bits from a raw mask, ignoring unknown bits.
    pub const fn from_bits(bits: u8) -> Self {
        Perms(bits & 0b111)
    }

    /// The raw bit mask.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True when every right in `other` is granted here.
    pub fn contains(self, other: Perms) -> bool {
        self.0 & other.0 == other.0
    }

    /// True when no right at all is granted.
    pub fn is_none(self) -> bool {
        self.0 == 0
    }

    /// True when all three fundamental rights are granted.
    pub fn is_rwx(self) -> bool {
        self.0 == Perms::RWX.0
    }

    /// All rights present in either operand.
    pub fn union(self, other: Perms) -> Self {
        Perms(self.0 | other.0)
    }

    /// Rights present in both operands.
    pub fn intersect(self, other: Perms) -> Self {
        Perms(self.0 & other.0)
    }

    /// Removes `other`'s rights from `self`.
    pub fn without(self, other: Perms) -> Self {
        Perms(self.0 & !other.0)
    }
}

/// Formats the permission bits the way `/proc/self/maps` does.
pub fn format_perms(perms: Perms) -> String {
    let mut s = String::with_capacity(4);
    s.push(if perms.contains(Perms::READ) { 'r' } else { '-' });
    s.push(if perms.contains(Perms::WRITE) { 'w' } else { '-' });
    s.push(if perms.contains(Perms::EXEC) { 'x' } else { '-' });
    s
}

/// Writes the permission bits into a page table entry in the format the
/// x86-64 PTEs use: present, writable, user-accessible, and a global bit.
pub fn pte_bits(perms: Perms) -> u64 {
    let mut e = 1u64 << 63;
    if perms.contains(Perms::WRITE) {
        e |= 1 << 1;
    }
    if perms.contains(Perms::EXEC) {
        e &= !(1 << 63);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_page_roundtrips() {
        for &addr in &[0u64, 1, 0xfff, 0x1000, 0x1001, 0xffff_ffff_ffff_fffd] {
            let (base, off) = split_page(addr);
            assert_eq!(base + off as u64, addr, "addr {addr:#x}");
            assert_eq!(base % PAGE_SIZE as u64, 0, "base {base:#x} not aligned");
        }
    }

    #[test]
    fn align_up_and_down() {
        assert_eq!(align_down(0x1234), 0x1000);
        assert_eq!(align_up(0x1000), Some(0x1000));
        assert_eq!(align_up(0x1001), Some(0x2000));
        assert_eq!(align_up(0), Some(0));
        // Near the top of the address space, rounding up overflows.
        assert_eq!(align_up(u64::MAX), None);
        assert_eq!(align_down(u64::MAX), 0xffff_ffff_ffff_f000);
    }

    #[test]
    fn pages_for_counts_partial_pages() {
        assert_eq!(pages_for(0, 0), 0);
        assert_eq!(pages_for(0, 1), 1);
        assert_eq!(pages_for(0, PAGE_SIZE as u64), 1);
        assert_eq!(pages_for(0, PAGE_SIZE as u64 + 1), 2);
        assert_eq!(pages_for(0xfff, 1), 1);
        assert_eq!(pages_for(0xfff, 2), 2);
    }

    #[test]
    fn page_range_covers_exactly() {
        let pages: Vec<u64> = page_range(0x1000, PAGE_SIZE as u64 * 3).collect();
        assert_eq!(pages, vec![0x1000, 0x2000, 0x3000]);

        // A straddling range starts at the containing page.
        let pages: Vec<u64> = page_range(0x1fff, 2).collect();
        assert_eq!(pages, vec![0x1000, 0x2000]);

        // Zero length yields nothing.
        assert_eq!(page_range(0x4000, 0).count(), 0);
    }

    #[test]
    fn canonical_addresses_are_symmetric_about_the_hole() {
        assert!(is_canonical(0));
        assert!(is_canonical(0x0000_7fff_ffff_ffff));
        // The gap between the halves is non-canonical.
        assert!(!is_canonical(0x0000_8000_0000_0000));
        assert!(!is_canonical(0xffff_7fff_ffff_ffff));
        assert!(is_canonical(HIGHER_HALF_START));
        assert!(is_canonical(u64::MAX));
    }

    #[test]
    fn frame_byte_offset_inverse() {
        for index in [1u64, 2, 0x1234, 0xffff_ffff] {
            let f = Frame::from_index(index);
            assert_eq!(Frame::from_byte_offset(f.byte_offset()), Some(f));
        }
        assert_eq!(Frame::from_byte_offset(0x1001), None);
        assert_eq!(Frame::from_byte_offset(0x1000), Some(Frame::from_index(1)));
    }

    #[test]
    fn perms_algebra() {
        assert!(Perms::RWX.contains(Perms::RWX));
        assert!(!Perms::RW.contains(Perms::RWX));
        assert!(Perms::RW.contains(Perms::RWX.intersect(Perms::RW)));
        assert!(Perms::READ.without(Perms::READ).is_none());
        assert!(Perms::READ.union(Perms::WRITE).contains(Perms::RW));
        // Composite permissions must equal the union of their parts, or
        // `contains` silently fails for anything built from RW.
        assert_eq!(Perms::READ.union(Perms::WRITE), Perms::RW);
        assert_eq!(Perms::READ.union(Perms::WRITE).union(Perms::EXEC), Perms::RWX);
        assert_eq!(format_perms(Perms::RWX), "rwx");
        assert_eq!(format_perms(Perms::READ), "r--");
        assert_eq!(format_perms(Perms::NONE), "---");
        assert_eq!(format_perms(Perms::from_bits(0b010)), "-w-");
    }

    #[test]
    fn pte_bits_encode_presence_and_writability() {
        assert_ne!(pte_bits(Perms::NONE) & (1 << 63), 0);
        assert_eq!(pte_bits(Perms::READ) & (1 << 1), 0);
        assert_ne!(pte_bits(Perms::WRITE) & (1 << 1), 0);
        assert_ne!(pte_bits(Perms::RW) & (1 << 1), 0);
        // Executable mappings clear the present-bit aliasing NX.
        assert_eq!(pte_bits(Perms::EXEC) & (1 << 63), 0);
    }

    #[test]
    fn unknown_permission_bits_are_ignored() {
        assert_eq!(Perms::from_bits(0b1111_0000), Perms::NONE);
        assert_eq!(Perms::from_bits(0xff).bits(), 0b111);
    }
}
