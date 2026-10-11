//! In-memory filesystem: inode tree, path resolution, and file operations.
//!
//! Deliberately independent of any block device. `BlockDev` is the seam, so a
//! RAM disk is used in tests and a host-backed device can be swapped in later
//! without touching any path logic.

use std::collections::BTreeMap;

/// Linux-compatible errno values, restricted to what the VFS needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Errno {
    Success = 0,
    NoEnt = 2,
    Io = 5,
    Badf = 9,
    Acces = 13,
    Exist = 17,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    NoMem = 12,
    NotEmpty = 39,
    NameTooLong = 36,
    TooManyLinks = 31,
    /// Unimplemented syscall. Linux value is 38.
    Nosys = 38,
    /// Syscall was interrupted. Linux value is 4.
    Intr = 4,
    /// Bad address. Linux value is 14.
    Fault = 14,
    /// Out of file descriptors. Linux value is 24.
    Mfile = 24,
    /// Result too large to fit. Linux value is 34.
    Range = 34,
    /// Try again. Linux value is 11.
    Again = 11,
    /// Operation not permitted. Linux value is 1.
    Perm = 1,
}

pub type VfsResult<T> = Result<T, Errno>;

/// A Linux-style `struct stat`, which is what `stat`/`fstat` return.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stat {
    /// Device id. A single in-memory filesystem, so this is always 0.
    pub dev: u64,
    pub ino: u64,
    /// Hard link count.
    pub nlink: u64,
    /// Unix mode bits, `S_IFREG`/`S_IFDIR` already ORed in.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Padding the Linux layout keeps before the size field.
    pub pad0: u32,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl Stat {
    /// Byte size of the guest struct this serialises into.
    pub const BYTE_LEN: usize = 144;

    /// Linux `S_IFMT` mask.
    pub const S_IFMT: u32 = 0o170000;
    /// Regular file.
    pub const S_IFREG: u32 = 0o100000;
    /// Directory.
    pub const S_IFDIR: u32 = 0o040000;

    pub fn is_dir(&self) -> bool {
        self.mode & Self::S_IFMT == Self::S_IFDIR
    }

    pub fn is_file(&self) -> bool {
        self.mode & Self::S_IFMT == Self::S_IFREG
    }

    /// Serialises to the exact Linux x86-64 layout, so a guest's `struct stat`
    /// needs no patching.
    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        let put = |out: &mut [u8; Self::BYTE_LEN], off: usize, bytes: &[u8]| {
            out[off..off + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut out, 0, &self.dev.to_le_bytes());
        put(&mut out, 8, &self.ino.to_le_bytes());
        put(&mut out, 16, &self.nlink.to_le_bytes());
        put(&mut out, 24, &self.mode.to_le_bytes());
        put(&mut out, 28, &self.uid.to_le_bytes());
        put(&mut out, 32, &self.gid.to_le_bytes());
        put(&mut out, 36, &self.pad0.to_le_bytes());
        put(&mut out, 40, &self.size.to_le_bytes());
        put(&mut out, 48, &self.blksize.to_le_bytes());
        put(&mut out, 56, &self.blocks.to_le_bytes());
        put(&mut out, 64, &self.atime_sec.to_le_bytes());
        put(&mut out, 72, &self.atime_nsec.to_le_bytes());
        put(&mut out, 80, &self.mtime_sec.to_le_bytes());
        put(&mut out, 88, &self.mtime_nsec.to_le_bytes());
        put(&mut out, 96, &self.ctime_sec.to_le_bytes());
        put(&mut out, 104, &self.ctime_nsec.to_le_bytes());
        out
    }

    /// Parses the guest struct. Returns `None` for a buffer that is too short.
    pub fn from_bytes(b: &[u8]) -> Option<Stat> {
        if b.len() < Self::BYTE_LEN {
            return None;
        }
        // Every read is bounds-checked against the length test above, so `unwrap` here
        // cannot actually fail.
        let word = |off: usize| -> [u8; 8] { b[off..off + 8].try_into().unwrap() };
        let dword = |off: usize| -> [u8; 4] { b[off..off + 4].try_into().unwrap() };
        let w = |off: usize| u64::from_le_bytes(word(off));
        let d = |off: usize| u32::from_le_bytes(dword(off));
        let s = |off: usize| i64::from_le_bytes(word(off));
        Some(Stat {
            dev: w(0),
            ino: w(8),
            nlink: w(16),
            mode: d(24),
            uid: d(28),
            gid: d(32),
            pad0: d(36),
            size: w(40),
            blksize: w(48),
            blocks: w(56),
            atime_sec: s(64),
            atime_nsec: s(72),
            mtime_sec: s(80),
            mtime_nsec: s(88),
            ctime_sec: s(96),
            ctime_nsec: s(104),
        })
    }
}

/// Identifies an inode within the filesystem.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Ino(pub u64);

/// What an inode represents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File(Vec<u8>),
    Dir(BTreeMap<String, Ino>),
}

impl NodeKind {
    pub fn is_dir(&self) -> bool {
        matches!(self, NodeKind::Dir(_))
    }

    pub fn is_file(&self) -> bool {
        matches!(self, NodeKind::File(_))
    }

    pub fn size(&self) -> u64 {
        match self {
            NodeKind::File(d) => d.len() as u64,
            NodeKind::Dir(_) => 0,
        }
    }
}

/// One filesystem node.
#[derive(Clone, Debug)]
pub struct Inode {
    pub ino: Ino,
    pub kind: NodeKind,
    /// Unix-style permission bits, `0o755`-style.
    pub mode: u32,
    pub nlink: u32,
}

/// Block-device seam. The in-memory VFS writes through this trait so that a
/// persistent implementation can be added without touching path resolution.
pub trait BlockDev {
    fn read_block(&self, block: u64, buf: &mut [u8]) -> VfsResult<()>;
    fn write_block(&mut self, block: u64, buf: &[u8]) -> VfsResult<()>;
    fn block_count(&self) -> u64;
}

/// A flat in-memory block device. Block size is fixed at one page, which
/// keeps the layout obvious in tests.
pub struct RamDisk {
    blocks: Vec<[u8; crate::addr::PAGE_SIZE]>,
}

impl Default for RamDisk {
    fn default() -> Self {
        Self::new(256)
    }
}

impl RamDisk {
    pub fn new(blocks: u64) -> Self {
        RamDisk {
            blocks: vec![[0u8; crate::addr::PAGE_SIZE]; blocks as usize],
        }
    }
}

impl BlockDev for RamDisk {
    fn read_block(&self, block: u64, buf: &mut [u8]) -> VfsResult<()> {
        let b = self.blocks.get(block as usize).ok_or(Errno::Io)?;
        let n = buf.len().min(b.len());
        buf[..n].copy_from_slice(&b[..n]);
        Ok(())
    }

    fn write_block(&mut self, block: u64, buf: &[u8]) -> VfsResult<()> {
        let b = self.blocks.get_mut(block as usize).ok_or(Errno::Io)?;
        let n = buf.len().min(b.len());
        b[..n].copy_from_slice(&buf[..n]);
        Ok(())
    }

    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }
}

/// Maximum length of a single path component, matching Linux.
pub const NAME_MAX: usize = 255;

/// Maximum length of a full path.
pub const PATH_MAX: usize = 4096;

/// The filesystem: a tree of inodes rooted at inode 1.
pub struct Vfs {
    inodes: BTreeMap<u64, Inode>,
    next_ino: u64,
}

/// An open file description.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fd(pub u32);

/// Flags accepted by `open`, encoded like Linux `O_*` for the subset used.
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_DIRECTORY: u32 = 0o200000;
/// Force every write to the current end of the file.
pub const O_APPEND: u32 = 0o2000;
/// Do not block. Advisory here: nothing in the VFS waits.
pub const O_NONBLOCK: u32 = 0o4000;
/// Close the descriptor on `execve`.
pub const O_CLOEXEC: u32 = 0o2000000;

/// Bits that select access mode rather than a modifier.
const O_ACCMODE: u32 = 3;

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    /// Creates a filesystem with an empty root directory.
    pub fn new() -> Self {
        let mut vfs = Vfs {
            inodes: BTreeMap::new(),
            next_ino: 2,
        };
        vfs.inodes.insert(
            1,
            Inode {
                ino: Ino(1),
                kind: NodeKind::Dir(BTreeMap::new()),
                mode: 0o755,
                nlink: 2,
            },
        );
        vfs
    }

    pub fn inode_count(&self) -> usize {
        self.inodes.len()
    }

    /// Fills in a `stat` for an inode.
    ///
    /// Timestamps come from `now` rather than being invented, so a guest that
    /// compares an `mtime` against its own clock sees a consistent value.
    pub fn stat(&self, ino: Ino, now: crate::clock::Timespec) -> VfsResult<Stat> {
        let node = self.get(ino)?;
        let ifmt = if node.kind.is_dir() {
            Stat::S_IFDIR
        } else {
            Stat::S_IFREG
        };
        let size = node.kind.size();
        Ok(Stat {
            dev: 0,
            ino: ino.0,
            nlink: if node.kind.is_dir() { 2 } else { 1 },
            mode: ifmt | (node.mode & 0o7777),
            uid: 0,
            gid: 0,
            pad0: 0,
            size,
            // 4 KiB blocks, rounding a short file up to one block, as Linux does.
            blksize: crate::addr::PAGE_SIZE as u64,
            blocks: size.div_ceil(512),
            atime_sec: now.sec,
            atime_nsec: now.nsec,
            mtime_sec: now.sec,
            mtime_nsec: now.nsec,
            ctime_sec: now.sec,
            ctime_nsec: now.nsec,
        })
    }

    /// Every inode, in inode order. Used by the persistence layer to walk the
    /// whole tree without repeating path resolution per node.
    pub fn nodes(&self) -> Vec<&Inode> {
        self.inodes.values().collect()
    }

    /// Full contents of a regular file, empty for anything else.
    pub fn contents(&self, ino: Ino) -> Vec<u8> {
        match &self.get(ino).map(|n| &n.kind) {
            Ok(NodeKind::File(d)) => d.clone(),
            _ => Vec::new(),
        }
    }

    /// Absolute path of an inode, or `/` for the root.
    ///
    /// Walks parent links upward by searching each directory for the child
    /// that points here. Bounded by the inode count, so a cycle cannot hang it.
    pub fn path_of(&self, target: Ino) -> String {
        if target == Ino(1) || !self.inodes.contains_key(&target.0) {
            return "/".to_string();
        }
        let mut parts: Vec<String> = Vec::new();
        let mut cur = target;
        for _ in 0..=self.inodes.len() {
            if cur == Ino(1) {
                break;
            }
            let Some((parent, name)) = self.parent_of(cur) else {
                break;
            };
            parts.push(name);
            cur = parent;
        }
        parts.reverse();
        if parts.is_empty() {
            return "/".to_string();
        }
        format!("/{}", parts.join("/"))
    }

    /// Finds the directory containing `target` and the name it is stored under.
    fn parent_of(&self, target: Ino) -> Option<(Ino, String)> {
        for (parent_ino, node) in &self.inodes {
            let NodeKind::Dir(children) = &node.kind else {
                continue;
            };
            for (name, child) in children {
                if *child == target {
                    return Some((Ino(*parent_ino), name.clone()));
                }
            }
        }
        None
    }

    pub fn get(&self, ino: Ino) -> VfsResult<&Inode> {
        self.inodes.get(&ino.0).ok_or(Errno::Badf)
    }

    pub fn get_mut(&mut self, ino: Ino) -> VfsResult<&mut Inode> {
        self.inodes.get_mut(&ino.0).ok_or(Errno::Badf)
    }

    /// Splits a path into components, resolving `.` and `..`.
    ///
    /// Returns `None` for a path that escapes the root via `..`, which is what
    /// keeps `/..` from reaching above the filesystem.
    pub fn normalize(path: &str) -> VfsResult<Vec<String>> {
        if path.len() > PATH_MAX {
            return Err(Errno::NameTooLong);
        }
        let mut out: Vec<String> = Vec::new();
        for comp in path.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    if out.pop().is_none() {
                        return Err(Errno::Acces);
                    }
                }
                c => {
                    if c.len() > NAME_MAX {
                        return Err(Errno::NameTooLong);
                    }
                    out.push(c.to_string());
                }
            }
        }
        Ok(out)
    }

    /// Resolves a path to an inode.
    pub fn lookup(&self, path: &str) -> VfsResult<Ino> {
        let comps = Self::normalize(path)?;
        let mut cur = Ino(1);
        for c in comps {
            let node = self.get(cur)?;
            let entries = match &node.kind {
                NodeKind::Dir(d) => d,
                NodeKind::File(_) => return Err(Errno::NotDir),
            };
            let next = entries.get(&c).copied().ok_or(Errno::NoEnt)?;
            cur = next;
        }
        Ok(cur)
    }

    /// Looks up the final component only, reporting whether it exists.
    pub fn lookup_parent(&self, path: &str) -> VfsResult<(Ino, String)> {
        let mut comps = Self::normalize(path)?;
        let last = comps.pop().ok_or(Errno::Inval)?;
        let parent_path = format!("/{}", comps.join("/"));
        let parent = if parent_path == "/" && comps.is_empty() {
            Ino(1)
        } else {
            self.lookup(&parent_path)?
        };
        match self.get(parent)?.kind {
            NodeKind::Dir(_) => {}
            NodeKind::File(_) => return Err(Errno::NotDir),
        }
        Ok((parent, last))
    }

    /// Creates a file, failing if it already exists.
    pub fn create(&mut self, path: &str, data: &[u8]) -> VfsResult<Ino> {
        let (parent, name) = self.lookup_parent(path)?;
        {
            let p = self.get(parent)?;
            if let NodeKind::Dir(d) = &p.kind {
                if d.contains_key(&name) {
                    return Err(Errno::Exist);
                }
            }
        }
        let ino = Ino(self.next_ino);
        self.next_ino += 1;
        self.inodes.insert(
            ino.0,
            Inode {
                ino,
                kind: NodeKind::File(data.to_vec()),
                mode: 0o644,
                nlink: 1,
            },
        );
        if let NodeKind::Dir(d) = &mut self.get_mut(parent)?.kind {
            d.insert(name, ino);
        } else {
            return Err(Errno::NotDir);
        }
        Ok(ino)
    }

    /// Creates a directory. Parent's link count grows, matching `mkdir`.
    pub fn mkdir(&mut self, path: &str) -> VfsResult<Ino> {
        let (parent, name) = self.lookup_parent(path)?;
        {
            let p = self.get(parent)?;
            if let NodeKind::Dir(d) = &p.kind {
                if d.contains_key(&name) {
                    return Err(Errno::Exist);
                }
            }
        }
        let ino = Ino(self.next_ino);
        self.next_ino += 1;
        self.inodes.insert(
            ino.0,
            Inode {
                ino,
                kind: NodeKind::Dir(BTreeMap::new()),
                mode: 0o755,
                nlink: 2,
            },
        );
        if let NodeKind::Dir(d) = &mut self.get_mut(parent)?.kind {
            d.insert(name, ino);
        } else {
            return Err(Errno::NotDir);
        }
        self.get_mut(parent)?.nlink += 1;
        Ok(ino)
    }

    /// Removes a file.
    pub fn unlink(&mut self, path: &str) -> VfsResult<()> {
        let (parent, name) = self.lookup_parent(path)?;
        let target = {
            let p = self.get(parent)?;
            let d = match &p.kind {
                NodeKind::Dir(d) => d,
                NodeKind::File(_) => return Err(Errno::NotDir),
            };
            *d.get(&name).ok_or(Errno::NoEnt)?
        };
        match &self.get(target)?.kind {
            NodeKind::File(_) => {}
            NodeKind::Dir(_) => return Err(Errno::IsDir),
        }
        if let NodeKind::Dir(d) = &mut self.get_mut(parent)?.kind {
            d.remove(&name);
        }
        self.inodes.remove(&target.0);
        Ok(())
    }

    /// Removes an empty directory.
    pub fn rmdir(&mut self, path: &str) -> VfsResult<()> {
        if Self::normalize(path)?.is_empty() {
            return Err(Errno::Acces);
        }
        let (parent, name) = self.lookup_parent(path)?;
        let target = {
            let p = self.get(parent)?;
            let d = match &p.kind {
                NodeKind::Dir(d) => d,
                NodeKind::File(_) => return Err(Errno::NotDir),
            };
            *d.get(&name).ok_or(Errno::NoEnt)?
        };
        let empty = match &self.get(target)?.kind {
            NodeKind::Dir(d) => d.is_empty(),
            NodeKind::File(_) => return Err(Errno::NotDir),
        };
        if !empty {
            return Err(Errno::NotEmpty);
        }
        if let NodeKind::Dir(d) = &mut self.get_mut(parent)?.kind {
            d.remove(&name);
        }
        self.inodes.remove(&target.0);
        self.get_mut(parent)?.nlink -= 1;
        Ok(())
    }

    /// Opens a path, honouring the subset of `O_*` flags used by the shell.
    pub fn open(&mut self, path: &str, flags: u32) -> VfsResult<Ino> {
        let accmode = flags & O_ACCMODE;
        let exists = self.lookup(path).ok();

        match exists {
            Some(ino) => {
                if flags & O_EXCL != 0 && flags & O_CREAT != 0 {
                    return Err(Errno::Exist);
                }
                if flags & O_DIRECTORY != 0 && !self.get(ino)?.kind.is_dir() {
                    return Err(Errno::NotDir);
                }
                if flags & O_TRUNC != 0 {
                    if let NodeKind::File(_) = &self.get(ino)?.kind {
                        self.get_mut(ino)?.kind = NodeKind::File(Vec::new());
                    }
                }
                Ok(ino)
            }
            None => {
                if flags & O_CREAT == 0 {
                    return Err(Errno::NoEnt);
                }
                if accmode == O_RDONLY {
                    // Linux allows O_RDONLY|O_CREAT; be permissive here.
                }
                self.create(path, &[])
            }
        }
    }

    /// Reads `len` bytes at `offset`.
    pub fn read(&self, ino: Ino, offset: u64, len: usize) -> VfsResult<Vec<u8>> {
        match &self.get(ino)?.kind {
            NodeKind::File(d) => {
                let start = offset.min(d.len() as u64) as usize;
                let end = (start + len).min(d.len());
                Ok(d[start..end].to_vec())
            }
            NodeKind::Dir(_) => Err(Errno::IsDir),
        }
    }

    /// Writes `data` at `offset`, extending the file and zero-filling any gap.
    pub fn write(&mut self, ino: Ino, offset: u64, data: &[u8]) -> VfsResult<usize> {
        let node = self.get_mut(ino)?;
        let buf = match &mut node.kind {
            NodeKind::File(d) => d,
            NodeKind::Dir(_) => return Err(Errno::IsDir),
        };
        let start = offset as usize;
        if start > buf.len() {
            buf.resize(start, 0);
        }
        let end = start + data.len();
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);
        Ok(data.len())
    }

    /// Creates `path` or replaces its contents entirely.
    ///
    /// `create` alone fails with `EEXIST` on a second call, which is correct
    /// for `open(O_CREAT|O_EXCL)` but wrong for "write this file". The
    /// persistence layer and the shell's redirection both want the latter.
    pub fn put(&mut self, path: &str, data: &[u8]) -> VfsResult<Ino> {
        if let Ok(ino) = self.lookup(path) {
            if self.get(ino)?.kind.is_dir() {
                return Err(Errno::IsDir);
            }
            let node = self.get_mut(ino)?;
            node.kind = NodeKind::File(data.to_vec());
            return Ok(ino);
        }
        self.create(path, data)
    }

    /// Truncates a file to `len`.
    pub fn truncate(&mut self, ino: Ino, len: u64) -> VfsResult<()> {
        let node = self.get_mut(ino)?;
        match &mut node.kind {
            NodeKind::File(d) => {
                d.resize(len as usize, 0);
                Ok(())
            }
            NodeKind::Dir(_) => Err(Errno::IsDir),
        }
    }

    /// Lists a directory's entries, sorted, excluding `.` and `..`.
    pub fn readdir(&self, ino: Ino) -> VfsResult<Vec<String>> {
        match &self.get(ino)?.kind {
            NodeKind::Dir(d) => Ok(d.keys().cloned().collect()),
            NodeKind::File(_) => Err(Errno::NotDir),
        }
    }

    /// Recursively walks the tree, returning every path visited.
    pub fn walk(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.walk_from(Ino(1), "", &mut out);
        out
    }

    fn walk_from(&self, ino: Ino, prefix: &str, out: &mut Vec<String>) {
        if let NodeKind::Dir(d) = &self.get(ino).unwrap().kind {
            for (name, child) in d {
                let p = format!("{}/{}", prefix, name);
                out.push(p.clone());
                self.walk_from(*child, &p, out);
            }
        }
    }

    /// Total bytes held in regular files.
    pub fn total_bytes(&self) -> u64 {
        self.inodes
            .values()
            .filter(|i| i.kind.is_file())
            .map(|i| i.kind.size())
            .sum()
    }
}

/// Tests for the metadata and path helpers.
#[cfg(test)]
mod node_tests {
    use super::*;
    use crate::clock::Timespec;

    fn now() -> Timespec {
        Timespec::new(1_700_000_000, 123)
    }

    #[test]
    fn put_replaces_existing_contents_and_creates_when_missing() {
        let mut f = Vfs::new();
        f.put("/a", b"one").unwrap();
        f.put("/a", b"two").unwrap();
        assert_eq!(f.contents(f.lookup("/a").unwrap()), b"two");
        // Replacing must not leave the old bytes behind.
        f.put("/a", b"x").unwrap();
        assert_eq!(f.contents(f.lookup("/a").unwrap()), b"x");
    }

    #[test]
    fn put_refuses_to_clobber_a_directory() {
        let mut f = Vfs::new();
        f.mkdir("/d").unwrap();
        assert_eq!(f.put("/d", b"x"), Err(Errno::IsDir));
    }

    #[test]
    fn put_creates_missing_parent_free_paths_only() {
        let mut f = Vfs::new();
        assert_eq!(f.put("/missing/file", b"x"), Err(Errno::NoEnt));
    }

    #[test]
    fn contents_of_a_directory_is_empty_rather_than_an_error() {
        let mut f = Vfs::new();
        f.mkdir("/d").unwrap();
        assert!(f.contents(f.lookup("/d").unwrap()).is_empty());
        assert!(f.contents(Ino(9999)).is_empty());
    }

    #[test]
    fn path_of_recovers_the_full_path() {
        let mut f = Vfs::new();
        f.mkdir("/a").unwrap();
        f.mkdir("/a/b").unwrap();
        f.create("/a/b/c", b"x").unwrap();
        assert_eq!(f.path_of(f.lookup("/a/b/c").unwrap()), "/a/b/c");
        assert_eq!(f.path_of(f.lookup("/a/b").unwrap()), "/a/b");
        assert_eq!(f.path_of(f.lookup("/a").unwrap()), "/a");
        assert_eq!(f.path_of(Ino(1)), "/");
    }

    #[test]
    fn path_of_unknown_inodes_is_root_not_a_panic() {
        let f = Vfs::new();
        assert_eq!(f.path_of(Ino(4242)), "/");
        assert_eq!(f.path_of(Ino(0)), "/");
    }

    #[test]
    fn stat_reports_file_type_and_size() {
        let mut f = Vfs::new();
        f.mkdir("/d").unwrap();
        let file = f.create("/f", b"hello").unwrap();
        let st = f.stat(file, now()).unwrap();
        assert!(st.is_file());
        assert!(!st.is_dir());
        assert_eq!(st.size, 5);
        assert_eq!(st.ino, file.0);
        assert_eq!(st.blksize, 4096);
        assert_eq!(st.blocks, 1);
    }

    #[test]
    fn stat_reports_directories_with_the_right_type_and_link_count() {
        let f = Vfs::new();
        let st = f.stat(Ino(1), now()).unwrap();
        assert!(st.is_dir());
        assert_eq!(st.nlink, 2);
        assert_eq!(st.mode & 0o777, 0o755);
    }

    #[test]
    fn stat_of_a_missing_inode_is_badf() {
        let f = Vfs::new();
        assert_eq!(f.stat(Ino(777), now()), Err(Errno::Badf));
    }

    #[test]
    fn stat_carries_the_supplied_timestamp_into_all_three_fields() {
        let mut f = Vfs::new();
        let ino = f.create("/f", b"x").unwrap();
        let st = f.stat(ino, now()).unwrap();
        assert_eq!(st.mtime_sec, 1_700_000_000);
        assert_eq!(st.mtime_nsec, 123);
        assert_eq!(st.atime_sec, st.mtime_sec);
        assert_eq!(st.ctime_sec, st.mtime_sec);
    }

    #[test]
    fn stat_bytes_round_trip_through_the_linux_layout() {
        let mut f = Vfs::new();
        let ino = f.create("/f", b"payload").unwrap();
        let st = f.stat(ino, now()).unwrap();
        let bytes = st.to_bytes();
        assert_eq!(bytes.len(), Stat::BYTE_LEN);
        assert_eq!(Stat::from_bytes(&bytes), Some(st));
    }

    #[test]
    fn stat_from_bytes_rejects_a_short_buffer() {
        assert_eq!(Stat::from_bytes(&[0u8; 8]), None);
        assert_eq!(Stat::from_bytes(&[0u8; Stat::BYTE_LEN - 1]), None);
        assert!(Stat::from_bytes(&[0u8; Stat::BYTE_LEN]).is_some());
    }

    #[test]
    fn an_empty_file_reports_zero_size_but_still_allocates_a_block() {
        let mut f = Vfs::new();
        let ino = f.create("/empty", b"").unwrap();
        let st = f.stat(ino, now()).unwrap();
        assert_eq!(st.size, 0);
        assert_eq!(st.blocks, 0);
    }

    #[test]
    fn nodes_lists_every_inode() {
        let mut f = Vfs::new();
        f.mkdir("/d").unwrap();
        f.create("/d/f", b"x").unwrap();
        assert_eq!(f.nodes().len(), f.inode_count());
        assert_eq!(f.nodes().len(), 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> Vfs {
        Vfs::new()
    }

    #[test]
    fn errno_values_are_the_linux_ones() {
        assert_eq!(Errno::Success as i32, 0);
        assert_eq!(Errno::NoEnt as i32, 2);
        assert_eq!(Errno::Io as i32, 5);
        assert_eq!(Errno::Badf as i32, 9);
        assert_eq!(Errno::NoMem as i32, 12);
        assert_eq!(Errno::Acces as i32, 13);
        assert_eq!(Errno::Exist as i32, 17);
        assert_eq!(Errno::NotDir as i32, 20);
        assert_eq!(Errno::IsDir as i32, 21);
        assert_eq!(Errno::Inval as i32, 22);
    }

    #[test]
    fn fresh_fs_has_only_root() {
        let f = fs();
        assert_eq!(f.inode_count(), 1);
        assert_eq!(f.readdir(Ino(1)).unwrap(), Vec::<String>::new());
        assert!(f.get(Ino(1)).unwrap().kind.is_dir());
    }

    #[test]
    fn normalize_resolves_dot_and_dotdot() {
        assert_eq!(Vfs::normalize("/a/b").unwrap(), vec!["a", "b"]);
        assert_eq!(Vfs::normalize("/a/./b").unwrap(), vec!["a", "b"]);
        assert_eq!(Vfs::normalize("/a//b").unwrap(), vec!["a", "b"]);
        assert_eq!(Vfs::normalize("/a/b/../c").unwrap(), vec!["a", "c"]);
        assert_eq!(Vfs::normalize("/").unwrap(), Vec::<String>::new());
        assert_eq!(Vfs::normalize("/a/b/").unwrap(), vec!["a", "b"]);
    }

    #[test]
    fn dotdot_cannot_escape_root() {
        assert_eq!(Vfs::normalize("/.."), Err(Errno::Acces));
        assert_eq!(Vfs::normalize("/a/../.."), Err(Errno::Acces));
        assert_eq!(Vfs::normalize("../x"), Err(Errno::Acces));
        // /a/.. is fine because it lands back on root.
        assert_eq!(Vfs::normalize("/a/..").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn overlong_names_are_rejected() {
        let long = "x".repeat(NAME_MAX + 1);
        assert_eq!(Vfs::normalize(&format!("/{long}")), Err(Errno::NameTooLong));
        let ok = "x".repeat(NAME_MAX);
        assert!(Vfs::normalize(&format!("/{ok}")).is_ok());

        let huge = "x".repeat(PATH_MAX + 1);
        assert_eq!(Vfs::normalize(&huge), Err(Errno::NameTooLong));
    }

    #[test]
    fn create_lookup_and_read_back() {
        let mut f = fs();
        f.create("/hello.txt", b"hi there").unwrap();

        let ino = f.lookup("/hello.txt").unwrap();
        assert_eq!(f.get(ino).unwrap().kind.size(), 8);
        assert_eq!(f.read(ino, 0, 100).unwrap(), b"hi there".to_vec());
        assert_eq!(f.read(ino, 3, 2).unwrap(), b"th".to_vec());
    }

    #[test]
    fn reading_past_end_returns_what_exists() {
        let mut f = fs();
        let ino = f.create("/f", b"abc").unwrap();
        assert_eq!(f.read(ino, 1, 100).unwrap(), b"bc".to_vec());
        assert_eq!(f.read(ino, 99, 10).unwrap(), Vec::<u8>::new());
        assert_eq!(f.read(ino, 3, 1).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn duplicate_create_fails() {
        let mut f = fs();
        f.create("/dup", b"x").unwrap();
        assert_eq!(f.create("/dup", b"y"), Err(Errno::Exist));
        assert_eq!(f.lookup("/dup").unwrap().0, 2);
    }

    #[test]
    fn missing_lookup_is_noent() {
        let f = fs();
        assert_eq!(f.lookup("/nope"), Err(Errno::NoEnt));
        assert_eq!(f.lookup("/a/b/c"), Err(Errno::NoEnt));
    }

    #[test]
    fn traversing_through_a_file_is_notdir() {
        let mut f = fs();
        f.create("/file", b"x").unwrap();
        assert_eq!(f.lookup("/file/child"), Err(Errno::NotDir));
    }

    #[test]
    fn mkdir_and_nested_paths() {
        let mut f = fs();
        f.mkdir("/usr").unwrap();
        f.mkdir("/usr/bin").unwrap();
        f.create("/usr/bin/tool", b"bin").unwrap();

        assert!(f.get(f.lookup("/usr/bin").unwrap()).unwrap().kind.is_dir());
        assert_eq!(
            f.read(f.lookup("/usr/bin/tool").unwrap(), 0, 3).unwrap(),
            b"bin".to_vec()
        );
        // Parent link counts: root 2, /usr 3.
        assert_eq!(f.get(f.lookup("/usr").unwrap()).unwrap().nlink, 3);
    }

    #[test]
    fn mkdir_duplicate_and_through_file() {
        let mut f = fs();
        f.mkdir("/d").unwrap();
        assert_eq!(f.mkdir("/d"), Err(Errno::Exist));

        f.create("/file", b"").unwrap();
        assert_eq!(f.mkdir("/file/under"), Err(Errno::NotDir));
    }

    #[test]
    fn unlink_removes_file_and_frees_inode() {
        let mut f = fs();
        f.create("/gone", b"x").unwrap();
        let before = f.inode_count();
        f.unlink("/gone").unwrap();
        assert_eq!(f.inode_count(), before - 1);
        assert_eq!(f.lookup("/gone"), Err(Errno::NoEnt));
        assert_eq!(f.unlink("/gone"), Err(Errno::NoEnt));
    }

    #[test]
    fn unlink_refuses_directories() {
        let mut f = fs();
        f.mkdir("/d").unwrap();
        assert_eq!(f.unlink("/d"), Err(Errno::IsDir));
    }

    #[test]
    fn rmdir_requires_empty_and_refuses_root() {
        let mut f = fs();
        f.mkdir("/d").unwrap();
        f.create("/d/f", b"").unwrap();
        assert_eq!(f.rmdir("/d"), Err(Errno::NotEmpty));

        f.unlink("/d/f").unwrap();
        f.rmdir("/d").unwrap();
        assert_eq!(f.lookup("/d"), Err(Errno::NoEnt));

        assert_eq!(f.rmdir("/"), Err(Errno::Acces));
    }

    #[test]
    fn rmdir_decrements_parent_links() {
        let mut f = fs();
        f.mkdir("/a").unwrap();
        f.mkdir("/a/b").unwrap();
        assert_eq!(f.get(f.lookup("/a").unwrap()).unwrap().nlink, 3);
        f.rmdir("/a/b").unwrap();
        assert_eq!(f.get(f.lookup("/a").unwrap()).unwrap().nlink, 2);
    }

    #[test]
    fn open_without_create_on_missing_fails() {
        let mut f = fs();
        assert_eq!(f.open("/missing", O_RDONLY), Err(Errno::NoEnt));
    }

    #[test]
    fn open_with_create_makes_the_file() {
        let mut f = fs();
        let ino = f.open("/new", O_RDWR | O_CREAT).unwrap();
        assert!(f.get(ino).unwrap().kind.is_file());
        // Second create must succeed rather than failing with EEXIST.
        f.open("/new", O_RDWR | O_CREAT).unwrap();
    }

    #[test]
    fn open_excl_create_conflicts() {
        let mut f = fs();
        f.open("/e", O_RDWR | O_CREAT | O_EXCL).unwrap();
        assert_eq!(f.open("/e", O_RDWR | O_CREAT | O_EXCL), Err(Errno::Exist));
    }

    #[test]
    fn open_directory_flag_rejects_files() {
        let mut f = fs();
        f.create("/f", b"").unwrap();
        assert_eq!(f.open("/f", O_RDONLY | O_DIRECTORY), Err(Errno::NotDir));
        assert!(f.open("/", O_RDONLY | O_DIRECTORY).is_ok());
    }

    #[test]
    fn open_trunc_empties_file() {
        let mut f = fs();
        let ino = f.create("/t", b"0123456789").unwrap();
        f.open("/t", O_RDWR | O_TRUNC).unwrap();
        assert_eq!(f.read(ino, 0, 100).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn readdir_lists_children_sorted() {
        let mut f = fs();
        f.mkdir("/b").unwrap();
        f.create("/a", b"").unwrap();
        f.create("/c", b"").unwrap();
        assert_eq!(f.readdir(Ino(1)).unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn readdir_on_file_is_notdir() {
        let mut f = fs();
        let ino = f.create("/f", b"").unwrap();
        assert_eq!(f.readdir(ino), Err(Errno::NotDir));
    }

    #[test]
    fn write_at_offset_zero_fills_gap() {
        let mut f = fs();
        let ino = f.create("/sparse", b"abc").unwrap();
        assert_eq!(f.write(ino, 8, b"Z").unwrap(), 1);
        let got = f.read(ino, 0, 9).unwrap();
        assert_eq!(&got[..3], b"abc");
        assert!(
            got[3..8].iter().all(|b| *b == 0),
            "gap must be zeroed: {got:?}"
        );
        assert_eq!(got[8], b'Z');
    }

    #[test]
    fn write_overwrites_in_place_and_grows() {
        let mut f = fs();
        let ino = f.create("/w", b"aaaa").unwrap();
        f.write(ino, 1, b"ZZ").unwrap();
        assert_eq!(f.read(ino, 0, 4).unwrap(), b"aZZa".to_vec());

        f.write(ino, 3, b"bbc").unwrap();
        assert_eq!(f.read(ino, 0, 6).unwrap(), b"aZZbbc".to_vec());
    }

    #[test]
    fn write_and_read_on_directory_rejected() {
        let mut f = fs();
        assert_eq!(f.write(Ino(1), 0, b"x"), Err(Errno::IsDir));
        assert_eq!(f.read(Ino(1), 0, 1), Err(Errno::IsDir));
        assert_eq!(f.truncate(Ino(1), 0), Err(Errno::IsDir));
    }

    #[test]
    fn truncate_extends_with_zeros() {
        let mut f = fs();
        let ino = f.create("/tr", b"abc").unwrap();
        f.truncate(ino, 6).unwrap();
        let got = f.read(ino, 0, 6).unwrap();
        assert_eq!(&got[..3], b"abc");
        assert!(got[3..].iter().all(|b| *b == 0));
    }

    #[test]
    fn walk_visits_every_path() {
        let mut f = fs();
        f.mkdir("/u").unwrap();
        f.mkdir("/u/b").unwrap();
        f.create("/u/b/exe", b"").unwrap();
        f.create("/top", b"").unwrap();

        let mut paths = f.walk();
        paths.sort();
        assert_eq!(paths, vec!["/top", "/u", "/u/b", "/u/b/exe"]);
    }

    #[test]
    fn unknown_inodes_report_badf() {
        let f = fs();
        assert_eq!(f.read(Ino(999), 0, 1).err(), Some(Errno::Badf));
        assert_eq!(f.get(Ino(999)).err(), Some(Errno::Badf));
        assert_eq!(f.readdir(Ino(0)).err(), Some(Errno::Badf));
    }

    #[test]
    fn ramdisk_roundtrip_and_bounds() {
        let mut d = RamDisk::new(4);
        assert_eq!(d.block_count(), 4);
        let mut buf = vec![0u8; 8];
        d.write_block(0, b"abcdefgh").unwrap();
        d.read_block(0, &mut buf).unwrap();
        assert_eq!(&buf[..8], b"abcdefgh");

        assert_eq!(d.write_block(99, b"x"), Err(Errno::Io));
        assert_eq!(d.read_block(99, &mut buf), Err(Errno::Io));
    }

    #[test]
    fn deeply_nested_creation_and_teardown() {
        let mut f = fs();
        f.mkdir("/a").unwrap();
        f.mkdir("/a/b").unwrap();
        f.mkdir("/a/b/c").unwrap();
        f.mkdir("/a/b/c/d").unwrap();
        f.create("/a/b/c/d/leaf", b"deep").unwrap();

        assert_eq!(
            f.read(f.lookup("/a/b/c/d/leaf").unwrap(), 0, 4).unwrap(),
            b"deep".to_vec()
        );
        // Clean teardown in reverse order.
        f.unlink("/a/b/c/d/leaf").unwrap();
        f.rmdir("/a/b/c/d").unwrap();
        f.rmdir("/a/b/c").unwrap();
        f.rmdir("/a/b").unwrap();
        f.rmdir("/a").unwrap();
        assert_eq!(f.inode_count(), 1);
        assert_eq!(f.total_bytes(), 0);
    }

    #[test]
    fn path_equivalence_via_lookup() {
        let mut f = fs();
        f.mkdir("/x").unwrap();
        f.create("/x/f", b"1").unwrap();
        let target = f.lookup("/x/f").unwrap();
        for p in ["/x/f", "/x/./f", "/x//f", "/x/y/../f", "//x//f"] {
            assert_eq!(f.lookup(p).unwrap(), target, "path {p}");
        }
    }
}

impl From<Fd> for Ino {
    fn from(fd: Fd) -> Ino {
        Ino(fd.0 as u64)
    }
}
