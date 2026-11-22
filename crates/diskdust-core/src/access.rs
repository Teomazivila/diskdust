//! macOS privacy permissions that change what a scan can see.

use std::io::ErrorKind;
use std::path::Path;

use crate::model::Os;

/// System Settings → Privacy & Security → Full Disk Access.
pub const FULL_DISK_ACCESS_SETTINGS: &str = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

/// Whether this process has Full Disk Access, probed by listing `~/.Trash`, which macOS refuses
/// without it. `None` on Linux or when the probe is inconclusive (no Trash folder).
pub fn has_full_disk_access(os: Os, home: &Path) -> Option<bool> {
    if os != Os::MacOs {
        return None;
    }
    match std::fs::read_dir(home.join(".Trash")) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Some(false),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn probes_the_trash() {
        let home = tempfile::tempdir().expect("tempdir");
        assert_eq!(has_full_disk_access(Os::MacOs, home.path()), None, "no Trash: inconclusive");
        let trash = home.path().join(".Trash");
        std::fs::create_dir(&trash).expect("mkdir");
        assert_eq!(has_full_disk_access(Os::MacOs, home.path()), Some(true));
        assert_eq!(has_full_disk_access(Os::Linux, home.path()), None);
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let probed = has_full_disk_access(Os::MacOs, home.path());
        // Root ignores permission bits (CI containers): the probe must match what the OS allowed.
        let readable = std::fs::read_dir(&trash).is_ok();
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
        assert_eq!(probed, Some(readable));
        assert!(FULL_DISK_ACCESS_SETTINGS.contains("Privacy_AllFiles"));
    }
}
