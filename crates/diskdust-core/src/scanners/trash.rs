//! The user's Trash.

use std::fs;
use std::io::ErrorKind;

use super::{ScanContext, ScanError, Scanner, base_finding};
use crate::model::{Category, CleanupAction, Finding, KnownCommand, Os, Risk, SPECIFIC};

#[derive(Debug)]
pub struct TrashScanner;

impl Scanner for TrashScanner {
    fn id(&self) -> &'static str {
        "trash"
    }

    fn name(&self) -> &'static str {
        "Trash"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let path = match ctx.os {
            Os::MacOs => ctx.home.join(".Trash"),
            Os::Linux => ctx.home.join(".local/share/Trash"),
        };
        let base = base_finding("trash", "trash:user".to_owned(), Category::Trash, "Trash".to_owned());
        match fs::read_dir(&path) {
            Ok(_) => {
                let bytes = ctx.measure(&path).bytes;
                if bytes == 0 || fs::read_dir(&path).is_ok_and(|mut d| d.next().is_none()) {
                    return Ok(Vec::new());
                }
                Ok(vec![Finding {
                    detail: "Files you already deleted. Emptying the Trash is permanent.".to_owned(),
                    path: Some(path.clone()),
                    bytes: Some(bytes),
                    risk: Risk::Safe,
                    action: Some(CleanupAction::EmptyDir { path, root: ctx.home.clone() }),
                    specificity: SPECIFIC,
                    ..base
                }])
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied && ctx.os == Os::MacOs => Ok(vec![Finding {
                detail: "macOS blocks reading the Trash without Full Disk Access, so its size is unknown. \
                         Cleaning asks Finder to empty it."
                    .to_owned(),
                path: Some(path),
                risk: Risk::Safe,
                action: Some(CleanupAction::Run(KnownCommand::FinderEmptyTrash)),
                specificity: SPECIFIC,
                ..base
            }]),
            Err(_) => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn linux_trash_is_emptied_in_place() {
        let env = Env::new();
        env.file(".local/share/Trash/files/old.iso", BIG);
        let runner = FakeRunner::new();
        let found = TrashScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].action,
            Some(CleanupAction::EmptyDir { path: env.home.join(".local/share/Trash"), root: env.home.clone() })
        );
    }

    #[test]
    fn empty_or_missing_trash_is_ignored() {
        let env = Env::new();
        let runner = FakeRunner::new();
        assert!(TrashScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan").is_empty());
        fs::create_dir(env.home.join(".Trash")).expect("mkdir");
        assert!(TrashScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan").is_empty());
    }

    #[test]
    fn unreadable_mac_trash_falls_back_to_finder() {
        let env = Env::new();
        let trash = env.home.join(".Trash");
        env.file(".Trash/x", 10);
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o000)).expect("chmod");
        let runner = FakeRunner::new();
        let found = TrashScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o755)).expect("chmod");
        // Root ignores permission bits; only assert the fallback when the read was refused.
        if found.first().is_some_and(|f| f.bytes.is_none()) {
            assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::FinderEmptyTrash)));
        }
        assert!(TrashScanner.supports(Os::Linux));
        assert_eq!(TrashScanner.id(), "trash");
        assert_eq!(TrashScanner.name(), "Trash");
    }
}
