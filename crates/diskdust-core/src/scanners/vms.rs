//! Virtual machine disks of Lima and Colima, shown for information: their space is reclaimed from
//! inside the VM (e.g. `docker system prune` there) or by deleting the VM with its own tool.

use std::path::Path;

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir};
use crate::model::{Category, Finding, Os, SPECIFIC};
use crate::size::allocated_bytes;

/// Disk image file names inside a Lima instance folder (`disk` replaced `diffdisk` in Lima 2.1;
/// older instances keep a `disk` symlink, which is skipped).
const DISK_FILES: [&str; 3] = ["disk", "diffdisk", "basedisk"];

#[derive(Debug)]
pub struct VmDisksScanner;

fn disk_bytes(instance: &Path) -> u64 {
    DISK_FILES
        .iter()
        .filter_map(|name| std::fs::symlink_metadata(instance.join(name)).ok())
        .filter(std::fs::Metadata::is_file)
        .map(|m| allocated_bytes(&m))
        .sum()
}

fn info(id: String, title: String, path: &Path, bytes: u64, detail: String) -> Finding {
    Finding {
        detail,
        path: Some(path.to_path_buf()),
        bytes: Some(bytes),
        specificity: SPECIFIC,
        ..base_finding("vms", id, Category::Containers, title)
    }
}

/// Instances and extra disks under one Lima home (`~/.lima` or Colima's `~/.colima/_lima`).
fn lima_home(ctx: &ScanContext<'_>, home: &Path, colima: bool) -> Vec<Finding> {
    let tool = if colima { "Colima" } else { "Lima" };
    let mut found = Vec::new();
    for dir in children(home).into_iter().filter(|p| is_real_dir(p)) {
        let name = file_name(&dir);
        if name == "_disks" {
            for disk in children(&dir).into_iter().filter(|p| is_real_dir(p)) {
                let Some(report) = ctx.measure(&disk) else { continue };
                if report.bytes >= MIN_BYTES {
                    let disk_name = file_name(&disk);
                    found.push(info(
                        format!("vms:{}", disk.display()),
                        format!("{tool} data disk {disk_name}"),
                        &disk,
                        report.bytes,
                        format!("Additional {tool} disk (info only). Delete it with `limactl disk delete {disk_name}` when no VM uses it."),
                    ));
                }
            }
            continue;
        }
        if name.starts_with('_') {
            continue;
        }
        let bytes = disk_bytes(&dir);
        if bytes >= MIN_BYTES {
            let how = if colima { "`colima delete`" } else { "`limactl delete`" };
            found.push(info(
                format!("vms:{}", dir.display()),
                format!("{tool} VM {name}"),
                &dir,
                bytes,
                format!(
                    "Virtual machine disk (info only). Free space inside the VM (e.g. `docker system prune` there), \
                     or remove the VM with {how}."
                ),
            ));
        }
    }
    found
}

impl Scanner for VmDisksScanner {
    fn id(&self) -> &'static str {
        "vms"
    }

    fn name(&self) -> &'static str {
        "Virtual machine disks"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let mut found = lima_home(ctx, &ctx.home.join(".lima"), false);
        found.extend(lima_home(ctx, &ctx.home.join(".colima/_lima"), true));
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};

    #[test]
    fn lima_and_colima_disks_are_informational() {
        let env = Env::new();
        env.file(".lima/dev/disk", BIG);
        env.file(".lima/dev/basedisk", BIG);
        env.file(".lima/dev/lima.yaml", 10);
        env.file(".lima/old/diffdisk", BIG);
        std::os::unix::fs::symlink("diffdisk", env.home.join(".lima/old/disk")).expect("symlink");
        env.file(".lima/_config/override.yaml", BIG);
        env.file(".lima/_disks/data/datadisk", BIG);
        env.file(".colima/_lima/colima/diffdisk", BIG);
        let runner = FakeRunner::new();
        let mut found = VmDisksScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        found.sort_by(|a, b| a.title.cmp(&b.title));
        let summary: Vec<_> = found.iter().map(|f| (f.title.as_str(), f.bytes.expect("bytes") / BIG as u64)).collect();
        assert_eq!(
            summary,
            [("Colima VM colima", 1), ("Lima VM dev", 2), ("Lima VM old", 1), ("Lima data disk data", 1)]
        );
        assert!(found.iter().all(|f| !f.is_actionable()));
        assert!(VmDisksScanner.supports(Os::Linux) && VmDisksScanner.id() == "vms");
        assert!(!VmDisksScanner.name().is_empty());
    }
}
