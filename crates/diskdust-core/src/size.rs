//! Parallel allocated-size calculation.
//!
//! Counts allocated blocks (real disk usage), never follows symlinks, never crosses into other
//! filesystems and stops early when cancelled.
//!
//! Hard links: a file with several links is only freed when *every* link is removed. The walker
//! counts how many links of each inode lie inside the measured tree; inodes fully inside count as
//! reclaimable once, inodes with links elsewhere (e.g. `node_modules` linked to the pnpm store)
//! are reported as [`SizeReport::shared`] instead.

use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::ops::Add;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;

/// Result of measuring a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeReport {
    /// Allocated bytes that removing the path would free.
    pub bytes: u64,
    /// Allocated bytes of hard-linked files that also have links outside the path; removing the
    /// path alone does not free them.
    pub shared: u64,
    /// Number of regular files counted (each hard-linked inode once).
    pub files: u64,
    /// Entries that could not be read (permission denied, vanished, …).
    pub skipped: u64,
    /// False when the walk was cut short by cancellation, so the figures are partial.
    pub complete: bool,
    /// Newest modification time of any file or folder inside (Unix seconds). Folder times
    /// matter: npm stores package files with a fixed 1985 timestamp, but the folders show when
    /// they were installed.
    pub newest: Option<i64>,
}

impl Default for SizeReport {
    fn default() -> Self {
        Self { bytes: 0, shared: 0, files: 0, skipped: 0, complete: true, newest: None }
    }
}

impl Add for SizeReport {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            bytes: self.bytes.saturating_add(rhs.bytes),
            shared: self.shared.saturating_add(rhs.shared),
            files: self.files + rhs.files,
            skipped: self.skipped + rhs.skipped,
            complete: self.complete && rhs.complete,
            newest: self.newest.max(rhs.newest),
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
    let walker = Walker { device: meta.dev(), links: Mutex::new(HashMap::new()), cancel };
    let tree = walker.entry(path, &meta);
    let links = walker.links.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
    links.into_values().fold(tree, |mut report, inode| {
        report.files += 1;
        if inode.seen >= inode.nlink {
            report.bytes = report.bytes.saturating_add(inode.bytes);
        } else {
            report.shared = report.shared.saturating_add(inode.bytes);
        }
        report
    })
}

/// A hard-linked inode met during the walk.
struct Inode {
    nlink: u64,
    seen: u64,
    bytes: u64,
}

struct Walker<'a> {
    device: u64,
    links: Mutex<HashMap<(u64, u64), Inode>>,
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
            let own = SizeReport { bytes: allocated_bytes(meta), newest: Some(meta.mtime()), ..SizeReport::default() };
            own + self.children(path)
        } else {
            SizeReport { newest: Some(meta.mtime()), ..self.file(meta) }
        }
    }

    /// Regular files with one link are counted directly; hard-linked ones are settled in
    /// [`measure`] once every link inside the tree has been seen.
    fn file(&self, meta: &Metadata) -> SizeReport {
        if meta.nlink() > 1 {
            let mut links = self.links.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            links
                .entry((meta.dev(), meta.ino()))
                .or_insert(Inode { nlink: meta.nlink(), seen: 0, bytes: allocated_bytes(meta) })
                .seen += 1;
            return SizeReport::default();
        }
        SizeReport { bytes: allocated_bytes(meta), files: 1, ..SizeReport::default() }
    }

    fn children(&self, dir: &Path) -> SizeReport {
        if self.cancel.load(Ordering::Relaxed) {
            return SizeReport { complete: false, ..SizeReport::default() };
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
    fn newest_modification_time_includes_folders() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = dir.path().join("node_modules/pkg");
        fs::create_dir_all(&pkg).expect("mkdir");
        let file = pkg.join("index.js");
        fs::write(&file, b"x").expect("write");
        // npm writes package files with a fixed old timestamp.
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_mins(8_319_375);
        fs::File::options().write(true).open(&file).expect("open").set_modified(old).expect("mtime");
        let report = measure(&dir.path().join("node_modules"), &not_cancelled());
        let folder = fs::metadata(&pkg).expect("meta").mtime();
        assert_eq!(report.newest, Some(folder));
        assert!(folder > 499_162_500);
        assert_eq!(measure(Path::new("/definitely/not/here"), &not_cancelled()).newest, None);
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
    fn hard_links_inside_the_tree_count_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("a"), vec![0u8; 400_000]).expect("write");
        fs::hard_link(dir.path().join("a"), dir.path().join("b")).expect("link");
        let report = measure(dir.path(), &not_cancelled());
        assert_eq!(report.files, 1);
        assert!(report.bytes >= 400_000 && report.bytes < 800_000, "{report:?}");
        assert_eq!(report.shared, 0);
    }

    #[test]
    fn hard_links_outside_the_tree_are_shared_not_reclaimable() {
        // pnpm layout: node_modules files are hard links into a content store elsewhere.
        let base = tempfile::tempdir().expect("tempdir");
        let (store, modules) = (base.path().join("store"), base.path().join("node_modules"));
        fs::create_dir_all(&store).expect("mkdir");
        fs::create_dir_all(&modules).expect("mkdir");
        fs::write(store.join("blob"), vec![1u8; 400_000]).expect("write");
        fs::hard_link(store.join("blob"), modules.join("index.js")).expect("link");
        fs::write(modules.join("own.js"), vec![2u8; 100_000]).expect("write");
        let report = measure(&modules, &not_cancelled());
        assert_eq!(report.files, 2);
        assert!(report.shared >= 400_000, "{report:?}");
        assert!(report.bytes >= 100_000 && report.bytes < 400_000, "{report:?}");
        // Measuring the parent sees both links: everything is reclaimable.
        let whole = measure(base.path(), &not_cancelled());
        assert_eq!(whole.shared, 0);
        assert!(whole.bytes >= 500_000);
    }

    #[test]
    fn missing_path_is_skipped() {
        let report = measure(Path::new("/definitely/not/here/diskdust"), &not_cancelled());
        assert_eq!(report, SizeReport { skipped: 1, ..SizeReport::default() });
    }

    #[test]
    fn cancellation_stops_descent() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("sub")).expect("mkdir");
        fs::write(dir.path().join("sub/f"), vec![0u8; 10_000]).expect("write");
        let report = measure(dir.path(), &AtomicBool::new(true));
        assert_eq!(report.files, 0);
        assert!(!report.complete, "a cancelled walk must be marked partial");
        assert!(measure(dir.path(), &not_cancelled()).complete);
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
    fn add_saturates_and_propagates_partial() {
        let a = SizeReport { bytes: u64::MAX, shared: 1, files: 1, skipped: 0, complete: true, newest: Some(5) };
        let b = SizeReport { bytes: 10, shared: u64::MAX, files: 2, skipped: 3, complete: false, newest: None };
        assert_eq!(
            a + b,
            SizeReport { bytes: u64::MAX, shared: u64::MAX, files: 3, skipped: 3, complete: false, newest: Some(5) }
        );
    }
}
