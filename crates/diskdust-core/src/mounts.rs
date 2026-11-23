//! Mount points, so cleaning never deletes into another file system.
//!
//! Sizes are measured without crossing file systems, but `remove_dir_all` (and moving a folder
//! to the Trash) would take a network share or bind mount inside the folder with it. The cleaner
//! therefore refuses any path that is, or contains, a mount point.
//!
//! A path-based "stop at mount boundaries" delete was deliberately not written: running as root it
//! would reintroduce the symlink races that `std::fs::remove_dir_all` is hardened against.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::CommandRunner;
use crate::model::Os;

/// The system's mount points, or why they could not be read (then cleaning fails closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    points: Result<Vec<PathBuf>, String>,
}

impl MountTable {
    /// Reads the current mount table: `/proc/self/mounts` on Linux, `mount` on macOS.
    pub fn current(os: Os, runner: &dyn CommandRunner) -> Self {
        let points = match os {
            Os::Linux => std::fs::read_to_string("/proc/self/mounts")
                .map(|text| parse_proc_mounts(&text))
                .map_err(|e| format!("cannot read /proc/self/mounts: {e}")),
            Os::MacOs => match runner.run(&["mount".to_owned()], Duration::from_secs(10)) {
                Ok(out) if out.success => Ok(parse_macos_mount(&out.stdout)),
                Ok(out) => Err(format!("`mount` failed: {}", out.stderr.trim())),
                Err(e) => Err(e.to_string()),
            },
        };
        Self { points }
    }

    /// An empty table: nothing mounted anywhere (tests).
    pub const fn none() -> Self {
        Self { points: Ok(Vec::new()) }
    }

    /// A table with the given mount points (tests and callers that already know them).
    pub fn from_points(points: Vec<PathBuf>) -> Self {
        Self { points: Ok(points) }
    }

    /// A table that could not be read.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self { points: Err(reason.into()) }
    }

    /// The first mount point that is `target` or lies inside it. `Err` when the table is unknown.
    pub fn mount_within(&self, target: &Path) -> Result<Option<&Path>, &str> {
        let points = self.points.as_ref().map_err(String::as_str)?;
        Ok(points.iter().map(PathBuf::as_path).find(|m| m.starts_with(target)))
    }
}

/// Mount points from `/proc/self/mounts`: the second field, with octal escapes (`\040` = space).
pub fn parse_proc_mounts(text: &str) -> Vec<PathBuf> {
    text.lines().filter_map(|line| line.split(' ').nth(1)).map(|field| PathBuf::from(unescape_octal(field))).collect()
}

fn unescape_octal(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal =
            bytes.get(i + 1..i + 4).filter(|d| bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)));
        if let Some(digits) = octal {
            out.push(digits.iter().fold(0u8, |acc, d| acc.wrapping_mul(8).wrapping_add(d - b'0')));
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Mount points from macOS `mount` output: `<device> on <path> (<options>)`. The device may
/// contain spaces (`map auto_home`), the path is between the first ` on ` and the last ` (`.
pub fn parse_macos_mount(text: &str) -> Vec<PathBuf> {
    text.lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once(" on ")?;
            let path = rest.rfind(" (").map_or(rest, |i| &rest[..i]);
            (!path.is_empty()).then(|| PathBuf::from(path))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;

    /// Captured from macOS 26 (`mount`), shortened.
    const MACOS: &str = "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n\
        devfs on /dev (devfs, local, nobrowse)\n\
        map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)\n\
        //u@nas/share on /Users/u/mnt/My Share (smbfs, nodev, nosuid, mounted by u)\n";

    #[test]
    fn parses_macos_mount_output() {
        assert_eq!(
            parse_macos_mount(MACOS),
            [
                PathBuf::from("/"),
                PathBuf::from("/dev"),
                PathBuf::from("/System/Volumes/Data/home"),
                PathBuf::from("/Users/u/mnt/My Share"),
            ]
        );
        assert!(parse_macos_mount("garbage\n").is_empty());
    }

    #[test]
    fn parses_proc_mounts_with_escapes() {
        let text = "proc /proc proc rw 0 0\n/dev/sdb1 /home/u/mnt/a\\040b ext4 rw 0 0\nnas:/x /home/u/back\\134slash nfs rw 0 0\n";
        assert_eq!(
            parse_proc_mounts(text),
            [PathBuf::from("/proc"), PathBuf::from("/home/u/mnt/a b"), PathBuf::from("/home/u/back\\slash")]
        );
        assert_eq!(unescape_octal("a\\04"), "a\\04", "incomplete escape is kept");
        assert_eq!(unescape_octal("a\\999"), "a\\999", "non-octal escape is kept");
    }

    #[test]
    fn finds_mounts_inside_a_target() {
        let table = MountTable::from_points(vec![PathBuf::from("/"), PathBuf::from("/Users/u/cache/remote")]);
        assert_eq!(table.mount_within(Path::new("/Users/u/cache")), Ok(Some(Path::new("/Users/u/cache/remote"))));
        assert_eq!(
            table.mount_within(Path::new("/Users/u/cache/remote")),
            Ok(Some(Path::new("/Users/u/cache/remote"))),
            "a mount point itself"
        );
        assert_eq!(table.mount_within(Path::new("/Users/u/cache/other")), Ok(None));
        assert_eq!(table.mount_within(Path::new("/Users/u/cach")), Ok(None), "component-wise, not string prefix");
        assert_eq!(MountTable::unknown("no table").mount_within(Path::new("/x")), Err("no table"));
    }

    #[test]
    fn reads_the_current_table() {
        let os = Os::current().expect("os");
        let runner = FakeRunner::new().respond("mount", true, MACOS);
        let table = MountTable::current(os, &runner);
        assert!(table.mount_within(Path::new("/")).is_ok_and(|m| m.is_some()), "{table:?}");
        if os == Os::MacOs {
            let failing = FakeRunner::new().respond("mount", false, "");
            assert!(MountTable::current(os, &failing).mount_within(Path::new("/")).is_err());
            assert!(MountTable::current(os, &FakeRunner::new()).mount_within(Path::new("/")).is_err());
        }
    }
}
