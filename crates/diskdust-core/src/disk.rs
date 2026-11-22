//! Free and total space of the file system holding a path.

use std::path::Path;

/// Space on one file system, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    /// Space available to an unprivileged user (`f_bavail`).
    pub available: u64,
    pub total: u64,
}

/// `statvfs` of `path`; `None` when it cannot be queried. On APFS, space macOS reports as
/// "purgeable" is not included in `available`.
pub fn space(path: &Path) -> Option<DiskSpace> {
    let stat = rustix::fs::statvfs(path).ok()?;
    let block = stat.f_frsize.max(1);
    Some(DiskSpace { available: stat.f_bavail.saturating_mul(block), total: stat.f_blocks.saturating_mul(block) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_space_of_existing_paths_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let space = space(dir.path()).expect("statvfs");
        assert!(space.total > 0 && space.available <= space.total, "{space:?}");
        assert!(super::space(Path::new("/definitely/not/here/diskdust")).is_none());
    }
}
