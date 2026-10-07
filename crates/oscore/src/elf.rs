//! ELF64 parsing and validation, plus loading into an `AddressSpace`.
//!
//! Parsing is pure byte inspection over a slice, so it is fully testable. The
//! tests build ELF images byte-by-byte rather than checking in binaries, which
//! keeps every field and every rejection path visible in source.

use crate::addr::{self, AddrError, Perms, PAGE_SIZE};
use crate::elf::class::{Class, Data, Type};
use crate::mem::MemBackend;
use crate::space::AddressSpace;

/// Size of the ELF64 identification block.
pub const EI_NIDENT: usize = 16;
/// Size of the ELF64 header.
pub const EHSIZE: usize = 64;
/// Size of one ELF64 program header.
pub const PHENTSIZE: usize = 56;

/// Rejection reasons. Each variant maps to a distinct `errno` later.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfError {
    /// Slice is shorter than a header.
    Truncated,
    /// `\x7fELF` missing.
    BadMagic,
    /// Unsupported ELF class (not 64-bit).
    BadClass,
    /// Unsupported byte order.
    BadEncoding,
    /// Unsupported ELF version.
    BadVersion,
    /// Object type cannot be executed.
    NotExecutable,
    /// Entry point is not canonical.
    BadEntryPoint,
    /// A program header runs past the end of the file.
    SegmentOutOfBounds,
    /// Program header count or offset is implausible.
    BadProgramHeaders,
    /// Overlapping loadable segments.
    OverlappingSegments,
    /// A segment would land at a non-canonical address.
    NonCanonicalSegment,
    /// Segment is not page aligned where it must be.
    MisalignedSegment,
    /// No loadable segment found.
    NoLoadableSegments,
}

impl ElfError {
    /// Stable short name, useful in test assertions and logs.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ElfError::Truncated => "truncated",
            ElfError::BadMagic => "bad-magic",
            ElfError::BadClass => "bad-class",
            ElfError::BadEncoding => "bad-encoding",
            ElfError::BadVersion => "bad-version",
            ElfError::NotExecutable => "not-executable",
            ElfError::BadEntryPoint => "bad-entry-point",
            ElfError::SegmentOutOfBounds => "segment-out-of-bounds",
            ElfError::BadProgramHeaders => "bad-program-headers",
            ElfError::OverlappingSegments => "overlapping-segments",
            ElfError::NonCanonicalSegment => "non-canonical-segment",
            ElfError::MisalignedSegment => "misaligned-segment",
            ElfError::NoLoadableSegments => "no-loadable-segments",
        }
    }
}

/// Parsed ELF64 file header.
#[derive(Clone, Copy, Debug)]
pub struct ElfHeader {
    pub class: Class,
    pub data: Data,
    pub version: u8,
    pub osabi: u8,
    pub etype: Type,
    pub machine: u16,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
}

impl ElfHeader {
    /// Parses and validates the file header.
    pub fn parse(bytes: &[u8]) -> Result<Self, ElfError> {
        if bytes.len() < EHSIZE {
            return Err(ElfError::Truncated);
        }
        if &bytes[0..4] != b"\x7fELF" {
            return Err(ElfError::BadMagic);
        }

        let class = match bytes[4] {
            1 => Class::Bits32,
            2 => Class::Bits64,
            _ => return Err(ElfError::BadClass),
        };
        if class != Class::Bits64 {
            return Err(ElfError::BadClass);
        }

        let data = match bytes[5] {
            1 => Data::LittleEndian,
            2 => Data::BigEndian,
            _ => return Err(ElfError::BadEncoding),
        };
        if data != Data::LittleEndian {
            return Err(ElfError::BadEncoding);
        }

        let version = bytes[6];
        if version != 1 {
            return Err(ElfError::BadVersion);
        }

        let etype = match Type::from_u16(u16::from_le_bytes([bytes[16], bytes[17]])) {
            Some(t) => t,
            None => return Err(ElfError::NotExecutable),
        };
        if etype != Type::Executable && etype != Type::SharedObject {
            return Err(ElfError::NotExecutable);
        }

        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        // x86-64 is 62. Anything else cannot run on this kernel.
        if machine != 62 {
            return Err(ElfError::NotExecutable);
        }

        let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        if entry != 0 && !addr::is_canonical(entry) {
            return Err(ElfError::BadEntryPoint);
        }

        let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap());

        let phentsize = u16::from_le_bytes([bytes[54], bytes[55]]);
        let phnum = u16::from_le_bytes([bytes[56], bytes[57]]);

        Ok(ElfHeader {
            class,
            data,
            version,
            osabi: bytes[7],
            etype,
            machine,
            entry,
            phoff,
            shoff,
            phentsize,
            phnum,
        })
    }
}

/// Parsed program header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProgramHeader {
    pub ptype: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PT_DYNAMIC: u32 = 2;

impl ProgramHeader {
    pub const PF_X: u32 = 1;
    pub const PF_W: u32 = 2;
    pub const PF_R: u32 = 4;

    pub fn parse(bytes: &[u8]) -> Self {
        ProgramHeader {
            ptype: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            offset: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            vaddr: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            paddr: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            filesz: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            memsz: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            align: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
        }
    }

    pub fn is_load(&self) -> bool {
        self.ptype == PT_LOAD
    }

    pub fn is_interp(&self) -> bool {
        self.ptype == PT_INTERP
    }

    /// Permissions as the address space understands them.
    ///
    /// `PF_R` is mandatory: a segment the guest cannot read is unusable, and
    /// this kernel models no write-only or exec-only mapping. Requiring it also
    /// keeps `PF_X` from implying readability, so an executable segment still
    /// needs `PF_R` to be mapped at all.
    pub fn perms(&self) -> Perms {
        if self.flags & Self::PF_R == 0 {
            return Perms::NONE;
        }
        let mut p = Perms::READ;
        if self.flags & Self::PF_W != 0 {
            p = p.union(Perms::WRITE);
        }
        if self.flags & Self::PF_X != 0 {
            p = p.union(Perms::EXEC);
        }
        p
    }

    /// Last byte covered by this segment in memory.
    pub fn mem_end(&self) -> Option<u64> {
        self.vaddr.checked_add(self.memsz)
    }

    /// Last byte of file content backing this segment.
    pub fn file_end(&self) -> Option<u64> {
        self.offset.checked_add(self.filesz)
    }
}

/// Builder for synthetic ELF images, so tests can express any malformed input
/// they need without checking in binary fixtures.
#[derive(Clone, Debug)]
pub struct ElfBuilder {
    bytes: Vec<u8>,
    phnum: u16,
}

impl ElfBuilder {
    /// Starts a minimal well-formed x86-64 `ET_EXEC` with `phnum` loadable
    /// segments all pointing at offset 0.
    pub fn minimal(phnum: u16) -> Self {
        let mut bytes = vec![0u8; EHSIZE + phnum as usize * PHENTSIZE];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        bytes[24..32].copy_from_slice(&0x4000_0000u64.to_le_bytes()); // e_entry
        bytes[32..40].copy_from_slice(&(EHSIZE as u64).to_le_bytes()); // e_phoff
        bytes[54..56].copy_from_slice(&(PHENTSIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&phnum.to_le_bytes());

        for i in 0..phnum as usize {
            let o = EHSIZE + i * PHENTSIZE;
            bytes[o..o + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            bytes[o + 4..o + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
            bytes[o + 8..o + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
            bytes[o + 16..o + 24]
                .copy_from_slice(&(0x4000_0000u64 + PAGE_SIZE as u64 * i as u64).to_le_bytes());
            bytes[o + 24..o + 32]
                .copy_from_slice(&(0x4000_0000u64 + PAGE_SIZE as u64 * i as u64).to_le_bytes());
            bytes[o + 32..o + 40].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            bytes[o + 40..o + 48].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            bytes[o + 48..o + 56].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
            // p_align
        }

        // Pad so every default segment's file range lies inside the image;
        // otherwise the default segments would fail validation by design.
        let needed = (EHSIZE + phnum as usize * PHENTSIZE).max(PAGE_SIZE as usize * phnum as usize);
        bytes.resize(needed, 0);

        ElfBuilder { bytes, phnum }
    }

    /// Appends raw bytes to the file, growing the image.
    pub fn append(&mut self, data: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(data);
        self
    }

    pub fn entry(mut self, v: u64) -> Self {
        self.bytes[24..32].copy_from_slice(&v.to_le_bytes());
        self
    }

    pub fn etype_(mut self, t: u16) -> Self {
        self.bytes[16..18].copy_from_slice(&t.to_le_bytes());
        self
    }

    pub fn machine(mut self, m: u16) -> Self {
        self.bytes[18..20].copy_from_slice(&m.to_le_bytes());
        self
    }

    pub fn ident_byte(mut self, index: usize, v: u8) -> Self {
        self.bytes[index] = v;
        self
    }

    pub fn phnum(mut self, n: u16) -> Self {
        self.bytes[56..58].copy_from_slice(&n.to_le_bytes());
        self.phnum = n;
        self
    }

    pub fn phentsize(mut self, n: u16) -> Self {
        self.bytes[54..56].copy_from_slice(&n.to_le_bytes());
        self
    }

    pub fn phoff(mut self, off: u64) -> Self {
        self.bytes[32..40].copy_from_slice(&off.to_le_bytes());
        self
    }

    /// Overwrites one program header field by byte offset within the table.
    pub fn ph_field(&mut self, index: usize, field_off: usize, bytes: &[u8]) -> &mut Self {
        let o = EHSIZE + index * PHENTSIZE + field_off;
        self.bytes[o..o + bytes.len()].copy_from_slice(bytes);
        self
    }

    pub fn ph_type(&mut self, index: usize, t: u32) -> &mut Self {
        self.ph_field(index, 0, &t.to_le_bytes())
    }

    pub fn ph_flags(&mut self, index: usize, f: u32) -> &mut Self {
        self.ph_field(index, 4, &f.to_le_bytes())
    }

    pub fn ph_vaddr(&mut self, index: usize, v: u64) -> &mut Self {
        self.ph_field(index, 16, &v.to_le_bytes())
    }

    pub fn ph_offset(&mut self, index: usize, v: u64) -> &mut Self {
        self.ph_field(index, 8, &v.to_le_bytes())
    }

    pub fn ph_filesz(&mut self, index: usize, v: u64) -> &mut Self {
        self.ph_field(index, 32, &v.to_le_bytes())
    }

    pub fn ph_memsz(&mut self, index: usize, v: u64) -> &mut Self {
        self.ph_field(index, 40, &v.to_le_bytes())
    }

    pub fn ph_align(&mut self, index: usize, v: u64) -> &mut Self {
        self.ph_field(index, 48, &v.to_le_bytes())
    }

    pub fn build(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// A validated ELF image ready to be mapped.
#[derive(Clone, Debug)]
pub struct ElfImage {
    pub header: ElfHeader,
    pub segments: Vec<ProgramHeader>,
}

impl ElfImage {
    /// Parses the header and all program headers, then validates the layout.
    pub fn parse(bytes: &[u8]) -> Result<Self, ElfError> {
        let header = ElfHeader::parse(bytes)?;

        if header.phnum == 0 {
            return Err(ElfError::NoLoadableSegments);
        }
        if header.phentsize as usize != PHENTSIZE {
            return Err(ElfError::BadProgramHeaders);
        }
        let table_bytes = (header.phnum as usize)
            .checked_mul(PHENTSIZE)
            .ok_or(ElfError::BadProgramHeaders)?;
        let table_end = header
            .phoff
            .checked_add(table_bytes as u64)
            .ok_or(ElfError::BadProgramHeaders)?;
        if table_end > bytes.len() as u64 {
            return Err(ElfError::BadProgramHeaders);
        }

        let mut segments = Vec::with_capacity(header.phnum as usize);
        for i in 0..header.phnum as usize {
            let start = (header.phoff as usize) + i * PHENTSIZE;
            let ph = ProgramHeader::parse(&bytes[start..start + PHENTSIZE]);
            segments.push(ph);
        }

        let image = ElfImage { header, segments };
        image.validate(bytes.len() as u64)?;
        Ok(image)
    }

    /// Checks that every loadable segment is in bounds, canonical, aligned,
    /// and non-overlapping.
    pub fn validate(&self, file_len: u64) -> Result<(), ElfError> {
        let mut loads: Vec<&ProgramHeader> = self.segments.iter().filter(|p| p.is_load()).collect();
        if loads.is_empty() {
            return Err(ElfError::NoLoadableSegments);
        }

        for ph in &loads {
            if let Some(end) = ph.file_end() {
                if end > file_len {
                    return Err(ElfError::SegmentOutOfBounds);
                }
            }
            if ph.filesz > ph.memsz {
                // .bss beyond file content is normal, the reverse is not.
                return Err(ElfError::SegmentOutOfBounds);
            }
            if ph.align > 1 {
                // The ELF rule is congruence, not zero: a segment's virtual
                // address and file offset must agree modulo the alignment.
                // Static glibc's RW segment, for instance, starts at file
                // offset `0xac108` mapped to virtual `0x4ac108`, both `0xc108`
                // past a page boundary. Requiring each to be page-aligned would
                // reject it even though the loader maps the page-aligned span.
                if ph.vaddr.abs_diff(ph.offset) % ph.align != 0 {
                    return Err(ElfError::MisalignedSegment);
                }
            }
            let end = ph.mem_end().ok_or(ElfError::SegmentOutOfBounds)?;
            if end > 0x0000_8000_0000_0000 {
                return Err(ElfError::NonCanonicalSegment);
            }
            if ph.vaddr != 0 && !addr::is_canonical(ph.vaddr) {
                return Err(ElfError::NonCanonicalSegment);
            }
        }

        loads.sort_by_key(|p| p.vaddr);
        for pair in loads.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if let Some(a_end) = a.mem_end() {
                if a_end > b.vaddr {
                    return Err(ElfError::OverlappingSegments);
                }
            }
        }

        Ok(())
    }

    /// Total span of virtual address space the image occupies.
    pub fn image_span(&self) -> Option<(u64, u64)> {
        let mut lo = u64::MAX;
        let mut hi = 0u64;
        for ph in self.segments.iter().filter(|p| p.is_load()) {
            lo = lo.min(ph.vaddr);
            hi = hi.max(ph.mem_end()?);
        }
        if lo == u64::MAX {
            None
        } else {
            Some((lo, hi))
        }
    }

    /// Maps every loadable segment into `space` with the requested rights.
    ///
    /// Frames come from `space`'s allocator and are zeroed, so the `.bss` tail
    /// (`memsz > filesz`) is already correct and needs no extra work.
    pub fn map_segments<M: MemBackend>(
        &self,
        space: &mut AddressSpace<M>,
    ) -> Result<(), AddrError> {
        for ph in self.segments.iter().filter(|p| p.is_load()) {
            let perms = ph.perms();
            if perms.is_none() {
                continue;
            }
            space.map_anon(ph.vaddr, ph.memsz, perms)?;
        }
        Ok(())
    }

    /// Maps segments and copies file content in from `bytes`.
    ///
    /// `bytes` must be the same image `parse` accepted.
    pub fn load<M: MemBackend>(
        &self,
        bytes: &[u8],
        space: &mut AddressSpace<M>,
    ) -> Result<(), AddrError> {
        for ph in self.segments.iter().filter(|p| p.is_load()) {
            let perms = ph.perms();
            if perms.is_none() {
                continue;
            }
            space.map_anon(ph.vaddr, ph.memsz, perms)?;

            if ph.filesz == 0 {
                continue;
            }
            let file_start = ph.offset as usize;
            let file_end = file_start + ph.filesz as usize;
            if file_end > bytes.len() {
                return Err(AddrError::OutOfRange);
            }
            space.write_bytes(ph.vaddr, &bytes[file_start..file_end])?;
        }
        Ok(())
    }
}

/// ELF header sub-structures and constants.
pub mod class {
    /// ELF class byte.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Class {
        Bits32 = 1,
        Bits64 = 2,
    }

    /// ELF data encoding byte.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Data {
        LittleEndian = 1,
        BigEndian = 2,
    }

    /// ELF object type.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Type {
        None = 0,
        Relocatable = 1,
        Executable = 2,
        SharedObject = 3,
        Core = 4,
    }

    impl Type {
        pub const fn from_u16(v: u16) -> Option<Self> {
            match v {
                0 => Some(Type::None),
                1 => Some(Type::Relocatable),
                2 => Some(Type::Executable),
                3 => Some(Type::SharedObject),
                4 => Some(Type::Core),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::SimMem;

    /// A single loadable segment image that validation accepts.
    fn good() -> ElfBuilder {
        ElfBuilder::minimal(1)
    }

    #[test]
    fn minimal_image_parses() {
        let b = good();
        let img = ElfImage::parse(b.as_slice()).expect("minimal image must parse");
        assert_eq!(img.header.class, Class::Bits64);
        assert_eq!(img.header.data, Data::LittleEndian);
        assert_eq!(img.header.version, 1);
        assert_eq!(img.header.etype, Type::Executable);
        assert_eq!(img.header.machine, 62);
        assert_eq!(img.header.entry, 0x4000_0000);
        assert_eq!(img.header.phnum, 1);
        assert_eq!(img.header.phentsize as usize, PHENTSIZE);
        assert_eq!(img.segments.len(), 1);
        assert!(img.segments[0].is_load());
    }

    #[test]
    fn rejects_truncated_input() {
        let short = vec![0u8; EHSIZE - 1];
        assert_eq!(ElfImage::parse(&short).unwrap_err(), ElfError::Truncated);
        assert_eq!(ElfImage::parse(&[]).unwrap_err(), ElfError::Truncated);
    }

    #[test]
    fn rejects_bad_magic() {
        let b = ElfBuilder::minimal(1);
        let mut bytes = b.build();
        bytes[1] = b'X';
        assert_eq!(ElfImage::parse(&bytes).unwrap_err(), ElfError::BadMagic);
    }

    #[test]
    fn rejects_wrong_class() {
        // ELFCLASS32 and an undefined class value are both rejected.
        assert_eq!(
            ElfImage::parse(good().ident_byte(4, 1).as_slice()).unwrap_err(),
            ElfError::BadClass,
        );
        assert_eq!(
            ElfImage::parse(good().ident_byte(4, 9).as_slice()).unwrap_err(),
            ElfError::BadClass,
        );
    }

    #[test]
    fn rejects_big_endian_and_unknown_encoding() {
        assert_eq!(
            ElfImage::parse(good().ident_byte(5, 2).as_slice()).unwrap_err(),
            ElfError::BadEncoding,
        );
        assert_eq!(
            ElfImage::parse(good().ident_byte(5, 7).as_slice()).unwrap_err(),
            ElfError::BadEncoding,
        );
    }

    #[test]
    fn rejects_bad_version() {
        assert_eq!(
            ElfImage::parse(good().ident_byte(6, 2).as_slice()).unwrap_err(),
            ElfError::BadVersion,
        );
    }

    #[test]
    fn rejects_non_executable_object_types() {
        for t in [0u16, 1, 4, 9] {
            assert_eq!(
                ElfImage::parse(good().etype_(t).as_slice()).unwrap_err(),
                ElfError::NotExecutable,
                "etype {t} must not be executable",
            );
        }
    }

    #[test]
    fn accepts_executable_and_shared_objects() {
        for t in [2u16, 3] {
            assert!(ElfImage::parse(good().etype_(t).as_slice()).is_ok());
        }
    }

    #[test]
    fn rejects_foreign_machine() {
        // 40 is EM_ARM, 3 is EM_386.
        for m in [3u16, 40, 183] {
            assert_eq!(
                ElfImage::parse(good().machine(m).as_slice()).unwrap_err(),
                ElfError::NotExecutable,
                "machine {m} must not run on this kernel",
            );
        }
    }

    #[test]
    fn rejects_non_canonical_entry_but_allows_zero() {
        assert_eq!(
            ElfImage::parse(good().entry(0x0000_8000_0000_0000).as_slice()).unwrap_err(),
            ElfError::BadEntryPoint,
        );
        assert!(
            ElfImage::parse(good().entry(0).as_slice()).is_ok(),
            "entry 0 is legal; it just cannot be jumped to"
        );
        assert!(ElfImage::parse(good().entry(0xffff_ffff_ffff_0000).as_slice()).is_ok());
    }

    #[test]
    fn rejects_zero_program_headers() {
        let b = good();
        assert_eq!(
            ElfImage::parse(b.phnum(0).as_slice()).unwrap_err(),
            ElfError::NoLoadableSegments,
        );
    }

    #[test]
    fn rejects_wrong_phentsize() {
        let b = good();
        assert_eq!(
            ElfImage::parse(b.phentsize(32).as_slice()).unwrap_err(),
            ElfError::BadProgramHeaders,
        );
    }

    #[test]
    fn rejects_program_header_table_outside_the_file() {
        assert_eq!(
            ElfImage::parse(good().phoff(0x1000_0000).as_slice()).unwrap_err(),
            ElfError::BadProgramHeaders,
        );
        // The second offset still yields a table that fits inside the image, so
        // it parses but exposes garbage headers rather than a bounds error.
        // Reaching the bounds check needs the table to end past the last byte.
        assert_eq!(
            ElfImage::parse(good().phoff((PAGE_SIZE) as u64).as_slice()).unwrap_err(),
            ElfError::BadProgramHeaders,
        );
    }

    #[test]
    fn rejects_segment_file_range_past_the_image() {
        let mut b = good();
        b.ph_filesz(0, PAGE_SIZE as u64 * 4);
        let bytes = b.build();
        assert_eq!(
            ElfImage::parse(&bytes).unwrap_err(),
            ElfError::SegmentOutOfBounds,
        );
    }

    #[test]
    fn rejects_filesz_larger_than_memsz() {
        let mut b = good();
        b.ph_memsz(0, 16);
        let bytes = b.build();
        assert_eq!(
            ElfImage::parse(&bytes).unwrap_err(),
            ElfError::SegmentOutOfBounds,
        );
    }

    #[test]
    fn accepts_bss_tail_where_memsz_exceeds_filesz() {
        let mut b = good();
        b.ph_filesz(0, 16).ph_memsz(0, PAGE_SIZE as u64);
        let img = ElfImage::parse(b.as_slice()).expect("a .bss tail is normal");
        let ph = img.segments[0];
        assert_eq!(ph.filesz, 16);
        assert_eq!(ph.memsz, PAGE_SIZE as u64);
    }

    #[test]
    fn rejects_misaligned_segment() {
        // align 4096 with a vaddr that is not a multiple of it.
        let mut b = good();
        b.ph_vaddr(0, 0x4000_0001);
        assert_eq!(
            ElfImage::parse(b.as_slice()).unwrap_err(),
            ElfError::MisalignedSegment,
        );
    }

    #[test]
    fn rejects_misaligned_file_offset() {
        // Keep filesz small so the segment stays inside the file and the
        // alignment rule is what rejects it, rather than the bounds rule.
        let mut b = good();
        b.ph_offset(0, 1).ph_filesz(0, 100);
        let bytes = b.build();
        assert_eq!(
            ElfImage::parse(&bytes).unwrap_err(),
            ElfError::MisalignedSegment,
        );
    }

    #[test]
    fn accepts_congruent_but_unaligned_segment() {
        // Static glibc maps file offset 0xac108 to virtual 0x4ac108: neither is
        // page-aligned, but they agree modulo the page size, which is all the
        // ELF format requires. The loader maps the page-aligned span.
        let mut b = good();
        b.ph_offset(0, 0x10)
            .ph_vaddr(0, 0x4000_0010)
            .ph_filesz(0, 0x10)
            .ph_memsz(0, 0x10);
        let bytes = b.build();
        assert!(ElfImage::parse(&bytes).is_ok());
    }

    #[test]
    fn rejects_segments_whose_end_overflows_the_address_space() {
        let mut b = good();
        b.ph_vaddr(0, 0x0000_7fff_ffff_f000).ph_memsz(0, 0x10_000);
        assert_eq!(
            ElfImage::parse(b.as_slice()).unwrap_err(),
            ElfError::NonCanonicalSegment,
        );
    }

    #[test]
    fn rejects_non_canonical_segment_start() {
        let mut b = good();
        b.ph_vaddr(0, 0xffff_8000_0000_0000);
        assert_eq!(
            ElfImage::parse(b.as_slice()).unwrap_err(),
            ElfError::NonCanonicalSegment,
        );
    }

    #[test]
    fn rejects_overlapping_segments() {
        let mut b = ElfBuilder::minimal(2);
        // Segment 0 covers page 0, segment 1 starts inside that same page.
        b.ph_vaddr(1, 0x4000_0000);
        assert_eq!(
            ElfImage::parse(b.as_slice()).unwrap_err(),
            ElfError::OverlappingSegments,
        );
    }

    #[test]
    fn accepts_adjacent_segments_touching_exactly() {
        let b = ElfBuilder::minimal(2);
        let img = ElfImage::parse(b.as_slice()).expect("end == start is not overlap");
        assert_eq!(img.segments[0].mem_end().unwrap(), img.segments[1].vaddr);
    }

    #[test]
    fn rejects_image_with_no_loadable_segments() {
        let mut b = good();
        b.ph_type(0, 2); // PT_INTERP-style, not PT_LOAD
        assert_eq!(
            ElfImage::parse(b.as_slice()).unwrap_err(),
            ElfError::NoLoadableSegments,
        );
    }

    #[test]
    fn image_span_covers_lowest_to_highest_load_segment() {
        let img = ElfImage::parse(ElfBuilder::minimal(3).as_slice()).unwrap();
        let (lo, hi) = img.image_span().unwrap();
        assert_eq!(lo, 0x4000_0000);
        assert_eq!(hi, 0x4000_0000 + 3 * PAGE_SIZE as u64);
    }

    #[test]
    fn segment_perms_are_derived_from_flags() {
        let ph = |flags: u32| ProgramHeader {
            ptype: PT_LOAD,
            flags,
            offset: 0,
            vaddr: 0,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            align: 1,
        };
        assert_eq!(ph(4).perms(), Perms::READ);
        assert_eq!(ph(6).perms(), Perms::READ.union(Perms::WRITE));
        assert_eq!(ph(5).perms(), Perms::READ.union(Perms::EXEC));
        assert_eq!(
            ph(7).perms(),
            Perms::READ.union(Perms::WRITE).union(Perms::EXEC)
        );
        assert!(ph(0).perms().is_none(), "no PF_R means unusable");
        assert!(ph(2).perms().is_none(), "write-only is unusable too");
    }

    #[test]
    fn map_segments_marks_pages_with_segment_permissions() {
        let b = ElfBuilder::minimal(2);
        let img = ElfImage::parse(b.as_slice()).unwrap();
        let mut space = AddressSpace::new(SimMem::new(64));
        img.map_segments(&mut space).unwrap();
        assert_eq!(space.table.len(), 2);
        assert_eq!(
            space.table.perms_at(0x4000_0000).unwrap(),
            Perms::READ.union(Perms::EXEC),
        );
        assert!(space
            .table
            .frame_at(0x4000_0000 + PAGE_SIZE as u64)
            .is_some());
        assert!(
            space
                .table
                .frame_at(0x4000_0000 + 2 * PAGE_SIZE as u64)
                .is_none(),
            "nothing past the last segment should be mapped",
        );
    }

    #[test]
    fn load_copies_file_content_to_the_segment_vaddr() {
        let mut b = ElfBuilder::minimal(1);
        b.ph_filesz(0, 8);
        let bytes = b.build();
        let img = ElfImage::parse(&bytes).unwrap();
        let mut space = AddressSpace::new(SimMem::new(64));
        img.load(&bytes, &mut space).unwrap();
        // Offset 0 is the ELF magic, so the segment now starts with \x7fELF.
        let got = space.read_bytes(0x4000_0000, 4).unwrap();
        assert_eq!(&got, b"\x7fELF");
    }

    #[test]
    fn load_leaves_bss_tail_zeroed() {
        let mut b = ElfBuilder::minimal(1);
        b.ph_filesz(0, 8).ph_memsz(0, PAGE_SIZE as u64);
        let bytes = b.build();
        let img = ElfImage::parse(&bytes).unwrap();
        let mut space = AddressSpace::new(SimMem::new(64));
        img.load(&bytes, &mut space).unwrap();
        let tail = space.read_bytes(0x4000_0000 + 8, 64).unwrap();
        assert!(tail.iter().all(|b| *b == 0), "fresh frames must be zeroed");
    }

    #[test]
    fn load_fails_when_the_image_is_shorter_than_the_segment() {
        let b = ElfBuilder::minimal(1);
        let img = ElfImage::parse(b.as_slice()).unwrap();
        // Hand `load` a truncated buffer it never validated against.
        let truncated = &b.as_slice()[..16];
        let mut space = AddressSpace::new(SimMem::new(64));
        assert_eq!(
            img.load(truncated, &mut space).unwrap_err(),
            AddrError::OutOfRange,
        );
    }

    #[test]
    fn load_fails_when_physical_memory_runs_out() {
        let b = ElfBuilder::minimal(2);
        let img = ElfImage::parse(b.as_slice()).unwrap();
        // One frame is not enough for two page-sized segments.
        let mut space = AddressSpace::new(SimMem::new(1));
        assert_eq!(
            img.load(b.as_slice(), &mut space).unwrap_err(),
            AddrError::OutOfRange,
            "a frame shortage must surface as an error, not a panic",
        );
    }

    #[test]
    fn builder_round_trips_a_two_segment_image() {
        let b = ElfBuilder::minimal(2).entry(0x4000_1000);
        let img = ElfImage::parse(b.as_slice()).unwrap();
        assert_eq!(img.header.entry, 0x4000_1000);
        assert_eq!(img.segments.len(), 2);
        assert_eq!(img.header.phnum, b.phnum);
    }

    #[test]
    fn mem_end_and_file_end_report_overflow_as_none() {
        let ph = ProgramHeader {
            ptype: PT_LOAD,
            flags: 4,
            offset: u64::MAX,
            vaddr: u64::MAX,
            paddr: 0,
            filesz: 1,
            memsz: 1,
            align: 1,
        };
        assert_eq!(ph.file_end(), None);
        assert_eq!(ph.mem_end(), None);
    }
}
