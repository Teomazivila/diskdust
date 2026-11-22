//! Parallel allocated-size calculation.
//!
//! Counts allocated blocks (real disk usage), never follows symlinks, never crosses into other
//! filesystems, counts hard-linked files once, and stops early when cancelled.

use std::collections::HashSet;
use std::fs::{self, Metadata};
use std::ops::Add;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;

/// Result of measuring a path.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SizeReport {
    /// Allocated bytes on disk.
    pub bytes: u64,
    /// Number of regular files counted.
    pub files: u64,
    /// Entries that could not be read (permission denied, vanished, …).
    pub skipped: u64,
}

impl Add for SizeReport {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            bytes: self.bytes.saturating_add(rhs.bytes),
            files: self.files + rhs.files,
            skipped: self.skipped + rhs.skipped,
        }
    }
}

/// Allocated bytes for a single metadata record.
pub fn allocated_bytes(meta: &Metadata) -> u64 {
    meta.blocks().saturating_mul(512)
}

/// Measures `path` recursively. Never fails: unreadable entries are counted in `skipped`.
pub fn measure(path: &Path, cancel: &AtomicBool) -> SizeReport {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return SizeReport { skipped: 1, ..SizeReport::default() };
    };
    let walker = Walker { device: meta.dev(), seen: Mutex::new(HashSet::new()), cancel };
    walker.entry(path, &meta)
}

struct Walker<'a> {
    device: u64,
    seen: Mutex<HashSet<(u64, u64)>>,
    cancel: &'a AtomicBool,
}

impl Walker<'_> {
    fn entry(&self, path: &Path, meta: &Metadata) -> SizeReport {
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            SizeReport::default()
        } else if file_type.is_dir() {
            if meta.dev() != self.device {
                return SizeReport::default();
            }
            let own = SizeReport { bytes: allocated_bytes(meta), ..SizeReport::default() };
            own + self.children(path)
        } else {
            self.file(meta)
        }
    }

    fn file(&self, meta: &Metadata) -> SizeReport {
        if meta.nlink() > 1 {
            let key = (meta.dev(), meta.ino());
            let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !seen.insert(key) {
                return SizeReport::default();
            }
        }
        SizeReport { bytes: allocated_bytes(meta), files: 1, skipped: 0 }
    }

    fn children(&self, dir: &Path) -> SizeReport {
        if self.cancel.load(Ordering::Relaxed) {
            return SizeReport::default();
        }
        let Ok(read) = fs::read_dir(dir) else {
            return SizeReport { skipped: 1, ..SizeReport::default() };
        };
        let mut skipped = 0;
        let entries: Vec<_> = read
            .filter_map(|entry| {
                if entry.is_err() {
                    skipped += 1;
                }
                entry.ok()
            })
            .collect();
        let base = SizeReport { skipped, ..SizeReport::default() };
        base + entries
            .par_iter()
            .map(|entry| {
                let path = entry.path();
                match fs::symlink_metadata(&path) {
                    Ok(meta) => self.entry(&path, &meta),
                    Err(_) => SizeReport { skipped: 1, ..SizeReport::default() },
                }
            })
            .reduce(SizeReport::default, Add::add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn not_cancelled() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn counts_nested_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("a/b/c")).expect("mkdir");
        fs::write(dir.path().join("a/one.bin"), vec![1u8; 100_000]).expect("write");
        fs::write(dir.path().join("a/b/c/two.bin"), vec![2u8; 50_000]).expect("write");
        let report = measure(dir.path(), &not_cancelled());
        assert_eq!(report.files, 2);
        assert!(report.bytes >= 150_000, "{report:?}");
        assert_eq!(report.skipped, 0);
    }

    #[test]
    fn single_file_is_measured() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f");
        fs::write(&file, vec![0u8; 8192]).expect("write");
        let report = measure(&file, &not_cancelled());
        assert_eq!(report.files, 1);
        assert!(report.bytes >= 8192);
    }

    #[test]
    fn does_not_follow_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let big = tempfile::tempdir().expect("tempdir");
        fs::write(big.path().join("huge.bin"), vec![0u8; 1_000_000]).expect("write");
        symlink(big.path(), dir.path().join("link")).expect("symlink");
        let report = measure(dir.path(), &not_cancelled());
        assert_eq!(report.files, 0);
        assert!(report.bytes < 1_000_000);
    }

    #[test]
    fn hard_links_counted_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("a"), vec![0u8; 400_000]).expect("write");
        fs::hard_link(dir.path().join("a"), dir.path().join("b")).expect("link");
        let report = measure(dir.path(), &not_cancelled());
        assert_eq!(report.files, 1);
        assert!(report.bytes < 800_000);
    }

    #[test]
    fn missing_path_is_skipped() {
        let report = measure(Path::new("/definitely/not/here/diskdust"), &not_cancelled());
        assert_eq!(report, SizeReport { bytes: 0, files: 0, skipped: 1 });
    }

    #[test]
    fn cancellation_stops_descent() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("sub")).expect("mkdir");
        fs::write(dir.path().join("sub/f"), vec![0u8; 10_000]).expect("write");
        let report = measure(dir.path(), &AtomicBool::new(true));
        assert_eq!(report.files, 0);
    }

    #[test]
    fn unreadable_directories_are_counted_as_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).expect("mkdir");
        fs::write(locked.join("f"), b"x").expect("write");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");
        let report = measure(dir.path(), &not_cancelled());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("chmod back");
        // Root bypasses permission bits (e.g. in CI containers); only assert when it applies.
        if report.files == 0 {
            assert_eq!(report.skipped, 1);
        }
    }

    #[test]
    fn add_saturates() {
        let a = SizeReport { bytes: u64::MAX, files: 1, skipped: 0 };
        let b = SizeReport { bytes: 10, files: 2, skipped: 3 };
        assert_eq!(a + b, SizeReport { bytes: u64::MAX, files: 3, skipped: 3 });
    }
}
