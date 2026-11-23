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

/// Change in available space between two measurements: positive when space was freed. `None`
/// when either measurement failed. Other programs writing at the same time also affect it, so it
/// is reported as a measurement, not as what the clean alone freed.
pub fn gained(before: Option<DiskSpace>, after: Option<DiskSpace>) -> Option<i64> {
    let (before, after) = (before?, after?);
    let delta = i128::from(after.available) - i128::from(before.available);
    Some(i64::try_from(delta).unwrap_or(if delta < 0 { i64::MIN } else { i64::MAX }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gain_is_the_change_in_available_space() {
        let at = |available| Some(DiskSpace { available, total: 100 });
        assert_eq!(gained(at(10), at(35)), Some(25));
        assert_eq!(gained(at(35), at(10)), Some(-25));
        assert_eq!(gained(None, at(10)), None);
        assert_eq!(gained(at(0), at(u64::MAX)), Some(i64::MAX), "saturates");
    }

    #[test]
    fn reports_space_of_existing_paths_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let space = space(dir.path()).expect("statvfs");
        assert!(space.total > 0 && space.available <= space.total, "{space:?}");
        assert!(super::space(Path::new("/definitely/not/here/diskdust")).is_none());
    }
}
