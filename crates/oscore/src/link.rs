//! Dynamic-linking support for static-PIE images.
//!
//! A static PIE (`ET_DYN` with no `PT_INTERP`) is fully linked, but its absolute
//! addresses are only known once a load base is chosen. It carries a `PT_DYNAMIC`
//! table describing self-relocations (`R_X86_64_RELATIVE`), and this module turns
//! those into concrete `(address, value)` stores for the host layer to perform.
//!
//! Nothing here touches memory or the filesystem: it is byte parsing over an
//! image plus an image's program headers, so every path is unit-tested.
//!
//! This is deliberately the whole loader. A static PIE has no undefined symbols,
//! so resolving names, mapping `DT_NEEDED` libraries and building a global
//! symbol table are unnecessary; only base-relative fixups remain.

use crate::elf::{ElfError, ElfImage, ProgramHeader, PT_DYNAMIC};

/// `DT_*` tags used by this loader.
pub const DT_NULL: i64 = 0;
/// A needed shared object (unused for a static PIE).
pub const DT_NEEDED: i64 = 1;
/// Size in bytes of the PLT relocation table.
pub const DT_PLTRELSZ: i64 = 2;
/// Address of the symbol string table (unused for a static PIE).
pub const DT_STRTAB: i64 = 5;
/// Address of the symbol table (unused for a static PIE).
pub const DT_SYMTAB: i64 = 6;
/// Address of the `Elf64_Rela` table.
pub const DT_RELA: i64 = 7;
/// Size in bytes of the `DT_RELA` table.
pub const DT_RELASZ: i64 = 8;
/// Size of one `Elf64_Rela`.
pub const DT_RELAENT: i64 = 9;
/// Address of the PLT relocation table.
pub const DT_JMPREL: i64 = 23;
/// Format of the PLT relocations (`DT_RELA` for relative entries).
pub const DT_PLTREL: i64 = 20;

/// `Elf64_Rela.r_info` low 32 bits: the relocation type.
pub const R_X86_64_NONE: u32 = 0;
/// A 64-bit absolute symbol reference.
pub const R_X86_64_64: u32 = 1;
/// A GOT entry holding a symbol's address.
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// A PLT slot holding a symbol's address.
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// A base-relative fixup: `value = base + addend`.
pub const R_X86_64_RELATIVE: u32 = 8;

/// One `Elf64_Rela` entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rela {
    /// Where the result is stored, relative to the image base.
    pub offset: u64,
    /// Symbol index (high 32 bits) and relocation type (low 32 bits).
    pub info: u64,
    /// Constant addend.
    pub addend: i64,
}

impl Rela {
    /// The relocation type (`R_X86_64_*`).
    pub fn rtype(&self) -> u32 {
        (self.info & 0xffff_ffff) as u32
    }

    /// The symbol table index (zero for `R_X86_64_RELATIVE`).
    pub fn rsym(&self) -> u32 {
        (self.info >> 32) as u32
    }
}

/// Returns the image's `PT_DYNAMIC` header, if it has one.
pub fn dynamic_header(image: &ElfImage) -> Option<ProgramHeader> {
    image
        .segments
        .iter()
        .find(|p| p.ptype == PT_DYNAMIC)
        .copied()
}

/// Parses the `(tag, value)` pairs of a `PT_DYNAMIC` segment, up to `DT_NULL`.
pub fn dynamic_table(bytes: &[u8], ph: &ProgramHeader) -> Result<Vec<(i64, i64)>, ElfError> {
    if ph.ptype != PT_DYNAMIC || ph.filesz % 16 != 0 {
        return Err(ElfError::BadProgramHeaders);
    }
    let start = ph.offset as usize;
    let end = start
        .checked_add(ph.filesz as usize)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    let raw = bytes.get(start..end).ok_or(ElfError::SegmentOutOfBounds)?;
    let mut out = Vec::with_capacity(raw.len() / 16);
    for chunk in raw.chunks_exact(16) {
        let tag = i64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let val = i64::from_le_bytes(chunk[8..16].try_into().unwrap());
        out.push((tag, val));
        if tag == DT_NULL {
            break;
        }
    }
    Ok(out)
}

/// Translates a virtual address to a file offset using the loadable segments.
pub fn vaddr_to_file(image: &ElfImage, vaddr: u64) -> Option<u64> {
    image.segments.iter().filter(|p| p.is_load()).find_map(|p| {
        let end = p.vaddr.checked_add(p.filesz)?;
        if vaddr >= p.vaddr && vaddr < end {
            Some(p.offset + (vaddr - p.vaddr))
        } else {
            None
        }
    })
}

/// Reads an `Elf64_Rela` table given its virtual address and size.
pub fn rela_table(
    bytes: &[u8],
    image: &ElfImage,
    vaddr: u64,
    size: u64,
    entsize: u64,
) -> Result<Vec<Rela>, ElfError> {
    if entsize != 0 && entsize != 24 {
        return Err(ElfError::BadProgramHeaders);
    }
    if size % 24 != 0 {
        return Err(ElfError::BadProgramHeaders);
    }
    let foff = vaddr_to_file(image, vaddr).ok_or(ElfError::SegmentOutOfBounds)?;
    let start = foff as usize;
    let end = start
        .checked_add(size as usize)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    let raw = bytes.get(start..end).ok_or(ElfError::SegmentOutOfBounds)?;
    let mut out = Vec::with_capacity(raw.len() / 24);
    for c in raw.chunks_exact(24) {
        out.push(Rela {
            offset: u64::from_le_bytes(c[0..8].try_into().unwrap()),
            info: u64::from_le_bytes(c[8..16].try_into().unwrap()),
            addend: i64::from_le_bytes(c[16..24].try_into().unwrap()),
        });
    }
    Ok(out)
}

/// Collects every `Elf64_Rela` of an image: `DT_RELA` plus `DT_JMPREL`.
pub fn relocations(bytes: &[u8], image: &ElfImage) -> Result<Vec<Rela>, ElfError> {
    let Some(ph) = dynamic_header(image) else {
        return Ok(Vec::new());
    };
    let entries = dynamic_table(bytes, &ph)?;

    let mut rela = None;
    let mut rela_sz = 0u64;
    let mut rela_ent = 24u64;
    let mut jmprel = None;
    let mut pltrelsz = 0u64;
    let mut pltrel = DT_RELA;
    for &(tag, val) in &entries {
        match tag {
            DT_RELA => rela = Some(val as u64),
            DT_RELASZ => rela_sz = val as u64,
            DT_RELAENT => rela_ent = val as u64,
            DT_JMPREL => jmprel = Some(val as u64),
            DT_PLTRELSZ => pltrelsz = val as u64,
            DT_PLTREL => pltrel = val,
            _ => {}
        }
    }

    let mut out = Vec::new();
    if let Some(va) = rela {
        out.extend(rela_table(bytes, image, va, rela_sz, rela_ent)?);
    }
    if let Some(va) = jmprel {
        if pltrel == DT_RELA {
            out.extend(rela_table(bytes, image, va, pltrelsz, 24)?);
        }
    }
    Ok(out)
}

/// Finalises the image by turning base-relative relocations into stores.
///
/// `write` receives `(address, value)` pairs; the host layer performs the actual
/// stores so this stays pure and testable. Only `R_X86_64_RELATIVE` (and the
/// no-op `R_X86_64_NONE`) is accepted: any other type means the image references
/// an undefined symbol, which a static PIE cannot, so it is rejected with the
/// offending type.
pub fn apply_static<F>(relocs: &[Rela], base: u64, mut write: F) -> Result<(), u32>
where
    F: FnMut(u64, u64),
{
    for r in relocs {
        match r.rtype() {
            R_X86_64_RELATIVE => {
                write(
                    base.wrapping_add(r.offset),
                    base.wrapping_add(r.addend as u64),
                );
            }
            R_X86_64_NONE => {}
            other => return Err(other),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::class::{Class, Data, Type};
    use crate::elf::{ElfHeader, ProgramHeader};

    fn load(offset: u64, vaddr: u64, filesz: u64) -> ProgramHeader {
        ProgramHeader {
            ptype: crate::elf::PT_LOAD,
            flags: ProgramHeader::PF_R,
            offset,
            vaddr,
            paddr: vaddr,
            filesz,
            memsz: filesz,
            align: 0x1000,
        }
    }

    fn image(segments: Vec<ProgramHeader>) -> ElfImage {
        ElfImage {
            header: ElfHeader {
                class: Class::Bits64,
                data: Data::LittleEndian,
                version: 1,
                osabi: 0,
                etype: Type::SharedObject,
                machine: 62,
                entry: 0,
                phoff: 0,
                shoff: 0,
                phentsize: 56,
                phnum: segments.len() as u16,
            },
            segments,
        }
    }

    fn put_u64(bytes: &mut [u8], at: usize, v: u64) {
        bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn rela_entry(bytes: &mut [u8], at: usize, offset: u64, info: u64, addend: i64) {
        put_u64(bytes, at, offset);
        put_u64(bytes, at + 8, info);
        put_u64(bytes, at + 16, addend as u64);
    }

    #[test]
    fn dynamic_table_reads_tags_until_null() {
        let mut bytes = vec![0u8; 0x40];
        put_u64(&mut bytes, 0x10, DT_RELA as u64);
        put_u64(&mut bytes, 0x18, 0x200);
        put_u64(&mut bytes, 0x20, DT_NULL as u64);
        // A trailing entry after DT_NULL must be ignored.
        put_u64(&mut bytes, 0x30, 0xdead);
        let ph = ProgramHeader {
            ptype: PT_DYNAMIC,
            filesz: 0x30,
            offset: 0x10,
            ..load(0, 0, 0)
        };
        let tags = dynamic_table(&bytes, &ph).unwrap();
        assert_eq!(tags, vec![(DT_RELA, 0x200), (DT_NULL, 0)]);
    }

    #[test]
    fn vaddr_to_file_maps_through_load_segments() {
        let img = image(vec![load(0x1000, 0x400000, 0x2000)]);
        assert_eq!(vaddr_to_file(&img, 0x400100), Some(0x1100));
        assert_eq!(vaddr_to_file(&img, 0x401fff), Some(0x2fff));
        assert_eq!(vaddr_to_file(&img, 0x420000), None);
    }

    #[test]
    fn rela_table_parses_entries() {
        let mut bytes = vec![0u8; 0x100];
        rela_entry(&mut bytes, 0x40, 0x5000, R_X86_64_RELATIVE as u64, 0x100);
        rela_entry(&mut bytes, 0x58, 0x5008, R_X86_64_RELATIVE as u64, 0x108);
        let img = image(vec![load(0, 0x4000, 0x100)]);
        let rs = rela_table(&bytes, &img, 0x4040, 48, 24).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].offset, 0x5000);
        assert_eq!(rs[0].rtype(), R_X86_64_RELATIVE);
        assert_eq!(rs[1].addend, 0x108);
    }

    #[test]
    fn relocations_combines_rela_and_jmprel() {
        let mut bytes = vec![0u8; 0x200];
        // DT table at 0x10.
        put_u64(&mut bytes, 0x10, DT_RELA as u64);
        put_u64(&mut bytes, 0x18, 0x4100);
        put_u64(&mut bytes, 0x20, DT_RELASZ as u64);
        put_u64(&mut bytes, 0x28, 24);
        put_u64(&mut bytes, 0x30, DT_JMPREL as u64);
        put_u64(&mut bytes, 0x38, 0x4160);
        put_u64(&mut bytes, 0x40, DT_PLTRELSZ as u64);
        put_u64(&mut bytes, 0x48, 24);
        put_u64(&mut bytes, 0x50, DT_PLTREL as u64);
        put_u64(&mut bytes, 0x58, DT_RELA as u64);
        put_u64(&mut bytes, 0x60, DT_NULL as u64);
        // One entry in each table.
        rela_entry(&mut bytes, 0x100, 0x5000, R_X86_64_RELATIVE as u64, 0x100);
        rela_entry(&mut bytes, 0x160, 0x5008, R_X86_64_RELATIVE as u64, 0x200);

        let ph = ProgramHeader {
            ptype: PT_DYNAMIC,
            offset: 0x10,
            filesz: 0x60,
            ..load(0, 0, 0)
        };
        let img = image(vec![load(0, 0x4000, 0x1000), ph]);
        let rs = relocations(&bytes, &img).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].offset, 0x5000);
        assert_eq!(rs[1].offset, 0x5008);
    }

    #[test]
    fn apply_static_writes_base_plus_addend() {
        let relocs = vec![
            Rela {
                offset: 0x5000,
                info: R_X86_64_RELATIVE as u64,
                addend: 0x303a,
            },
            Rela {
                offset: 0x5008,
                info: R_X86_64_RELATIVE as u64,
                addend: 0x3040,
            },
            Rela {
                offset: 0x5010,
                info: R_X86_64_NONE as u64,
                addend: 0,
            },
        ];
        let mut stores = Vec::new();
        apply_static(&relocs, 0x10000, |a, v| stores.push((a, v))).unwrap();
        assert_eq!(stores, vec![(0x15000, 0x1303a), (0x15008, 0x13040)]);
    }

    #[test]
    fn apply_static_rejects_symbol_relocations() {
        let relocs = vec![Rela {
            offset: 0x1000,
            info: R_X86_64_GLOB_DAT as u64,
            addend: 0,
        }];
        assert_eq!(apply_static(&relocs, 0, |_, _| {}), Err(R_X86_64_GLOB_DAT));
    }
}
