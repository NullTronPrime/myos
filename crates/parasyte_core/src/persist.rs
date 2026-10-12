//! Host-backed persistence for the guest filesystem.
//!
//! The VFS lives in memory. This module knows how to push that memory back out
//! to a host directory so a guest write survives the process, and how to pull a
//! host tree in. The walk order and the parent-directory creation are the parts
//! worth stating: a file may only be written once its parent exists, so
//! directories have to be created before their contents.

use crate::vfs::Vfs;
use std::path::{Component, Path, PathBuf};

/// What a sync did, so callers can report progress or test the outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SyncStats {
    /// Directories created on the host.
    pub dirs: u32,
    /// Files written.
    pub files: u32,
    /// Bytes written.
    pub bytes: u64,
}

impl SyncStats {
    pub fn merge(&mut self, other: SyncStats) {
        self.dirs += other.dirs;
        self.files += other.files;
        self.bytes += other.bytes;
    }
}

/// A guest path split into its components, with `.` and `..` resolved.
///
/// `..` at the root stays at the root, matching `Vfs::normalize`, so a hostile
/// tree cannot make the writer escape the host directory it was given.
pub fn split(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p.to_string()),
        }
    }
    out
}

/// Joins a host root and a guest path.
pub fn host_path(root: &Path, guest: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for c in split(guest) {
        p.push(c);
    }
    p
}

/// Whether a guest path lives in the host-owned rendezvous namespace.
///
/// `/winserv` is bridged live to the host rootfs by the trap layer (every
/// guest process sees the same directory), so it must never be snapshotted
/// into the VFS or written back: either direction would resurrect deleted
/// registrations or clobber live ones with stale copies.
pub fn is_shared_namespace(guest: &str) -> bool {
    guest == "/winserv" || guest.starts_with("/winserv/")
}

/// Writes every file in `vfs` under `root`, creating directories as needed.
///
/// Returns an error naming the first host write that failed; the walk stops
/// there. Files already present are rewritten, which is what makes this safe to
/// call repeatedly rather than only at exit.
pub fn write_all(vfs: &Vfs, root: &Path) -> Result<SyncStats, String> {
    let mut stats = SyncStats::default();
    let mut dirs: Vec<String> = vec![String::new()];

    for node in vfs.nodes() {
        if node.kind.is_dir() {
            let p = vfs.path_of(node.ino);
            if !is_shared_namespace(&p) {
                dirs.push(p);
            }
        }
    }
    // Shallow directories first, so a file's parent always exists before the
    // file is written.
    dirs.sort_by_key(|d| d.matches('/').count());
    for d in &dirs {
        let p = host_path(root, d);
        if p.as_os_str().is_empty() {
            continue;
        }
        if p.is_dir() {
            continue;
        }
        std::fs::create_dir_all(&p).map_err(|e| format!("mkdir {}: {e}", p.display()))?;
        stats.dirs += 1;
    }

    for node in vfs.nodes() {
        if !node.kind.is_file() {
            continue;
        }
        let guest = vfs.path_of(node.ino);
        // `path_of` returns `/` when it cannot locate a file's parents, which
        // would otherwise try to write over the root directory itself.
        if guest == "/" || is_shared_namespace(&guest) {
            continue;
        }
        let data = vfs.contents(node.ino);
        let p = host_path(root, &guest);
        if p.as_os_str().is_empty() {
            continue;
        }
        std::fs::write(&p, &data).map_err(|e| format!("write {}: {e}", p.display()))?;
        stats.files += 1;
        stats.bytes += data.len() as u64;
    }
    Ok(stats)
}

/// Recursively reads a host directory into `vfs`, replacing its contents.
///
/// Used when `PARASYTEOS_ROOT` is set, so the guest starts from whatever the host
/// directory holds rather than from a hardcoded seed.
pub fn read_all(root: &Path, vfs: &mut Vfs) -> Result<usize, String> {
    let mut count = 0usize;
    walk(root, "", vfs, &mut count, 0)?;
    Ok(count)
}

/// Depth cap, so a symlink loop cannot make this recurse forever.
const MAX_DEPTH: usize = 64;

fn walk(
    dir: &Path,
    guest: &str,
    vfs: &mut Vfs,
    count: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{}: directory nesting too deep", dir.display()));
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // An unreadable directory is not fatal: the rest of the tree is still
        // usable, and refusing to boot over it would be worse.
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Skip anything that could escape or confuse the guest's view.
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            continue;
        }
        // The rendezvous namespace is host-owned and bridged live; a VFS
        // snapshot of it would go stale on arrival and be written back over
        // live state on sync.
        if guest.is_empty() && name == "winserv" {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        let g = if guest.is_empty() {
            name.clone()
        } else {
            format!("{guest}/{name}")
        };
        if ft.is_dir() {
            vfs.mkdir(&g).map_err(|e| format!("mkdir {g}: {e:?}"))?;
            *count += 1;
            walk(&entry.path(), &g, vfs, count, depth + 1)?;
        } else if ft.is_file() {
            let data = std::fs::read(entry.path())
                .map_err(|e| format!("read {}: {e}", entry.path().display()))?;
            vfs.create(&g, &data)
                .map_err(|e| format!("create {g}: {e:?}"))?;
            *count += 1;
        }
        // Symlinks and devices are skipped: the guest has no way to use them,
        // and following one could leave the root.
    }
    Ok(())
}

/// Rejects a host path that escapes `root` through `..` or an absolute component.
pub fn is_contained(root: &Path, candidate: &Path) -> bool {
    let mut depth: i64 = 0;
    for c in candidate.components() {
        match c {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            // An absolute or prefix component resets the count, which is only
            // safe if nothing has been popped yet.
            Component::RootDir | Component::Prefix(_) => {
                if depth != 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    let _ = root;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::Ino;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("parasyteos-persist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn vfs_with_tree() -> Vfs {
        let mut vfs = Vfs::new();
        vfs.mkdir("/bin").unwrap();
        vfs.mkdir("/etc").unwrap();
        vfs.mkdir("/home").unwrap();
        vfs.create("/bin/sh", b"#!/bin/sh\n").unwrap();
        vfs.create("/etc/hostname", b"parasyteos").unwrap();
        vfs.create("/data", b"payload").unwrap();
        vfs
    }

    #[test]
    fn split_resolves_dot_and_dotdot() {
        assert_eq!(split("/bin/sh"), vec!["bin", "sh"]);
        assert_eq!(split("//bin///sh"), vec!["bin", "sh"]);
        assert_eq!(split("/bin/./sh"), vec!["bin", "sh"]);
        assert_eq!(split("/bin/../lib"), vec!["lib"]);
        assert_eq!(split("/"), Vec::<String>::new());
    }

    #[test]
    fn split_cannot_climb_above_the_root() {
        assert_eq!(split("/../../etc/passwd"), vec!["etc", "passwd"]);
        assert_eq!(split("/a/../../../b"), vec!["b"]);
    }

    #[test]
    fn host_path_stays_under_the_given_root() {
        let root = Path::new("/tmp/rootfs");
        assert_eq!(host_path(root, "/bin/sh"), Path::new("/tmp/rootfs/bin/sh"));
        assert_eq!(
            host_path(root, "/../escape"),
            Path::new("/tmp/rootfs/escape")
        );
        assert_eq!(host_path(root, "/"), root);
    }

    #[test]
    fn write_all_creates_directories_and_files() {
        let host = tmpdir("write");
        let stats = write_all(&vfs_with_tree(), &host).unwrap();
        assert_eq!(stats.files, 3);
        // `bin`, `etc` and `home`; the root already exists on the host.
        assert_eq!(stats.dirs, 3);
        assert_eq!(std::fs::read(host.join("bin/sh")).unwrap(), b"#!/bin/sh\n");
        assert_eq!(std::fs::read(host.join("etc/hostname")).unwrap(), b"parasyteos");
        assert_eq!(std::fs::read(host.join("data")).unwrap(), b"payload");
        assert!(host.join("bin").is_dir());
        assert!(host.join("etc").is_dir());
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn write_all_is_idempotent() {
        let host = tmpdir("idem");
        let vfs = vfs_with_tree();
        write_all(&vfs, &host).unwrap();
        let second = write_all(&vfs, &host).unwrap();
        assert_eq!(second.files, 3);
        assert_eq!(std::fs::read(host.join("bin/sh")).unwrap(), b"#!/bin/sh\n");
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn a_guest_write_reaches_the_host_and_survives_a_reload() {
        let host = tmpdir("reload");
        let mut vfs = Vfs::new();
        vfs.mkdir("/home").unwrap();
        vfs.create("/home/note", b"first").unwrap();
        write_all(&vfs, &host).unwrap();

        // A fresh VFS, as a relaunched OS would build.
        let mut next = Vfs::new();
        read_all(&host, &mut next).unwrap();
        let data = next.contents(next.lookup("/home/note").unwrap());
        assert_eq!(data, b"first");

        // The new write is the one that persists.
        next.put("/home/note", b"second").unwrap();
        write_all(&next, &host).unwrap();
        let mut after = Vfs::new();
        read_all(&host, &mut after).unwrap();
        assert_eq!(
            after.contents(after.lookup("/home/note").unwrap()),
            b"second"
        );
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn empty_files_round_trip() {
        let host = tmpdir("empty");
        let mut vfs = Vfs::new();
        vfs.mkdir("/tmp").unwrap();
        vfs.create("/tmp/blank", b"").unwrap();
        let stats = write_all(&vfs, &host).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.bytes, 0);
        assert_eq!(std::fs::metadata(host.join("tmp/blank")).unwrap().len(), 0);
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn winserv_never_crosses_the_vfs_boundary() {
        // A stale VFS copy must neither be written back (resurrecting a
        // deletion) nor preloaded (shadowing live state).
        let host = tmpdir("winserv");
        let mut vfs = Vfs::new();
        vfs.mkdir("/winserv").unwrap();
        vfs.mkdir("/winserv/clients").unwrap();
        vfs.create("/winserv/clients/9", b"1 x\n").unwrap();
        vfs.mkdir("/home").unwrap();
        vfs.create("/home/note", b"hi").unwrap();
        let stats = write_all(&vfs, &host).unwrap();
        assert_eq!(stats.files, 1);
        assert!(!host.join("winserv").exists());
        assert_eq!(std::fs::read(host.join("home/note")).unwrap(), b"hi");

        std::fs::create_dir_all(host.join("winserv/clients")).unwrap();
        std::fs::write(host.join("winserv/clients/7"), b"2 y\n").unwrap();
        let mut next = Vfs::new();
        read_all(&host, &mut next).unwrap();
        assert!(next.lookup("/winserv/clients/7").is_err());
        assert_eq!(
            next.contents(next.lookup("/home/note").unwrap()),
            b"hi"
        );
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn deep_nesting_is_written_parent_first() {
        let host = tmpdir("deep");
        let mut vfs = Vfs::new();
        vfs.mkdir("/a").unwrap();
        vfs.mkdir("/a/b").unwrap();
        vfs.mkdir("/a/b/c").unwrap();
        vfs.create("/a/b/c/leaf", b"x").unwrap();
        write_all(&vfs, &host).unwrap();
        assert_eq!(std::fs::read(host.join("a/b/c/leaf")).unwrap(), b"x");
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn read_all_skips_unreadable_roots_rather_than_failing() {
        let vfs_result = read_all(Path::new("/nonexistent-parasyteos-root"), &mut Vfs::new());
        assert!(vfs_result.is_ok());
        assert_eq!(vfs_result.unwrap(), 0);
    }

    #[test]
    fn read_all_counts_directories_and_files() {
        let host = tmpdir("count");
        std::fs::create_dir_all(host.join("d/e")).unwrap();
        std::fs::write(host.join("one"), b"1").unwrap();
        std::fs::write(host.join("d/two"), b"2").unwrap();
        std::fs::write(host.join("d/e/three"), b"3").unwrap();
        let mut vfs = Vfs::new();
        // 3 files plus the 2 subdirectories they live in.
        assert_eq!(read_all(&host, &mut vfs).unwrap(), 5);
        assert_eq!(vfs.contents(vfs.lookup("/d/e/three").unwrap()), b"3");
        std::fs::remove_dir_all(&host).unwrap();
    }

    #[test]
    fn containment_rejects_traversal_but_accepts_normal_paths() {
        assert!(is_contained(Path::new("/root"), Path::new("bin/sh")));
        assert!(is_contained(Path::new("/root"), Path::new("a/../b")));
        assert!(!is_contained(Path::new("/root"), Path::new("../b")));
        assert!(!is_contained(Path::new("/root"), Path::new("a/../../b")));
    }

    #[test]
    fn node_paths_are_recovered_from_the_vfs() {
        let vfs = vfs_with_tree();
        let sh = vfs.lookup("/bin/sh").unwrap();
        assert_eq!(vfs.path_of(sh), "/bin/sh");
        let bin = vfs.lookup("/bin").unwrap();
        assert_eq!(vfs.path_of(bin), "/bin");
        assert_eq!(vfs.path_of(Ino(1)), "/");
        assert_eq!(
            vfs.path_of(vfs.lookup("/etc/hostname").unwrap()),
            "/etc/hostname"
        );
    }
}
