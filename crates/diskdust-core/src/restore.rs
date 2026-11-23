//! Undo for Trash-mode cleans: put the items a clean moved to the Trash back where they were.
//!
//! The audit log says which paths a run moved to the Trash and when. On Linux (freedesktop Trash)
//! each one is matched to the Trash entry with the same original path deleted no earlier than the
//! run, and restored. Nothing is ever overwritten: if something exists at the original path again,
//! that item is left in the Trash. macOS offers no API to list or restore Trash items (and
//! `~/.Trash` needs Full Disk Access), so there [`SystemTrashStore`] reports that restoring is not
//! supported and callers show the items so the user can put them back from Finder.

use std::ffi::OsString;
use std::path::PathBuf;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::audit::AuditEntry;
use crate::clean::DeleteMode;
use crate::model::CleanupAction;

/// Seconds of slack between the audit timestamp and the Trash's own deletion time.
const CLOCK_SLACK: i64 = 120;

/// An item a clean moved to the Trash, from the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trashed {
    pub title: String,
    pub path: PathBuf,
    /// When the clean recorded it (Unix seconds).
    pub when: i64,
}

/// Items that run `run_id` successfully moved to the Trash.
pub fn trashed_in_run(entries: &[AuditEntry], run_id: &str) -> Vec<Trashed> {
    entries
        .iter()
        .filter(|e| e.run_id == run_id && e.ok && !e.elevated && e.mode == DeleteMode::Trash)
        .filter_map(|e| {
            let CleanupAction::RemovePath { path, .. } = &e.action else { return None };
            let when = OffsetDateTime::parse(&e.timestamp, &Rfc3339).ok()?.unix_timestamp();
            Some(Trashed { title: e.title.clone(), path: path.clone(), when })
        })
        .collect()
}

/// The most recent run that moved anything to the Trash, by timestamp, so the order of `entries`
/// does not matter (`AuditLog::read_recent` returns them newest first).
pub fn last_trash_run(entries: &[AuditEntry]) -> Option<String> {
    entries
        .iter()
        .filter(|e| !e.run_id.is_empty())
        .filter_map(|e| trashed_in_run(std::slice::from_ref(e), &e.run_id).first().map(|t| (t.when, &e.run_id)))
        .max_by_key(|(when, _)| *when)
        .map(|(_, run)| run.clone())
}

/// One entry of the platform Trash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashEntry {
    pub id: OsString,
    pub original_path: PathBuf,
    /// Unix seconds.
    pub time_deleted: i64,
}

/// Lists and restores Trash entries.
pub trait TrashStore {
    fn list(&self) -> Result<Vec<TrashEntry>, String>;
    fn restore(&self, entry: &TrashEntry) -> Result<(), String>;
}

/// What happened to one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restored {
    Restored,
    /// No matching entry: the item was restored already or the Trash was emptied.
    NotInTrash,
    /// Something exists at the original path again; it is never overwritten.
    PathExists,
    Failed(String),
}

/// Restores `items`; `Err` when the Trash cannot be listed at all (e.g. on macOS).
pub fn restore(items: &[Trashed], store: &dyn TrashStore) -> Result<Vec<(Trashed, Restored)>, String> {
    let entries = store.list()?;
    Ok(items
        .iter()
        .map(|item| {
            let candidate = entries
                .iter()
                .filter(|e| e.original_path == item.path && e.time_deleted >= item.when - CLOCK_SLACK)
                .max_by_key(|e| e.time_deleted);
            // Look for the Trash entry first: "already restored" is "not in the Trash", not a clash.
            let outcome = match candidate {
                None => Restored::NotInTrash,
                Some(_) if std::fs::symlink_metadata(&item.path).is_ok() => Restored::PathExists,
                Some(entry) => match store.restore(entry) {
                    Ok(()) => Restored::Restored,
                    Err(e) => Restored::Failed(e),
                },
            };
            (item.clone(), outcome)
        })
        .collect())
}

/// The platform Trash.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTrashStore;

/// Why restoring is unavailable on macOS, with what to do instead.
pub const MACOS_RESTORE_HINT: &str = "macOS does not let apps restore items from the Trash. Open the Trash in \
     Finder and drag the items back (or use Put Back where Finder offers it).";

#[cfg(target_os = "linux")]
impl TrashStore for SystemTrashStore {
    fn list(&self) -> Result<Vec<TrashEntry>, String> {
        let items = trash::os_limited::list().map_err(|e| e.to_string())?;
        Ok(items
            .into_iter()
            .map(|i| TrashEntry { original_path: i.original_path(), time_deleted: i.time_deleted, id: i.id })
            .collect())
    }

    fn restore(&self, entry: &TrashEntry) -> Result<(), String> {
        let item = trash::os_limited::list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|i| i.id == entry.id)
            .ok_or_else(|| "no longer in the Trash".to_owned())?;
        trash::os_limited::restore_all([item]).map_err(|e| e.to_string())
    }
}

#[cfg(not(target_os = "linux"))]
impl TrashStore for SystemTrashStore {
    fn list(&self) -> Result<Vec<TrashEntry>, String> {
        Err(MACOS_RESTORE_HINT.to_owned())
    }

    fn restore(&self, _entry: &TrashEntry) -> Result<(), String> {
        Err(MACOS_RESTORE_HINT.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::KnownCommand;
    use std::cell::RefCell;
    use std::path::Path;

    fn entry(run: &str, ts: &str, path: &str, mode: DeleteMode, ok: bool) -> AuditEntry {
        AuditEntry {
            timestamp: ts.into(),
            run_id: run.into(),
            finding_id: path.into(),
            title: path.into(),
            path: Some(path.into()),
            bytes: Some(1),
            action: CleanupAction::RemovePath { path: path.into(), root: "/".into() },
            mode,
            elevated: false,
            ok,
            message: String::new(),
        }
    }

    #[derive(Default)]
    struct FakeStore {
        entries: Vec<TrashEntry>,
        restored: RefCell<Vec<PathBuf>>,
        unsupported: bool,
    }

    impl TrashStore for FakeStore {
        fn list(&self) -> Result<Vec<TrashEntry>, String> {
            if self.unsupported { Err(MACOS_RESTORE_HINT.to_owned()) } else { Ok(self.entries.clone()) }
        }

        fn restore(&self, entry: &TrashEntry) -> Result<(), String> {
            self.restored.borrow_mut().push(entry.original_path.clone());
            Ok(())
        }
    }

    fn trash_entry(id: &str, path: &Path, time_deleted: i64) -> TrashEntry {
        TrashEntry { id: id.into(), original_path: path.to_path_buf(), time_deleted }
    }

    #[test]
    fn picks_trashed_items_of_a_run() {
        let mut admin = entry("r1", "2026-11-23T10:00:00Z", "/x/admin", DeleteMode::Trash, true);
        admin.elevated = true;
        let mut command = entry("r1", "2026-11-23T10:00:00Z", "/x/cmd", DeleteMode::Trash, true);
        command.action = CleanupAction::Run(KnownCommand::BrewCleanup);
        let entries = vec![
            entry("r1", "2026-11-23T10:00:00Z", "/x/a", DeleteMode::Trash, true),
            entry("r1", "2026-11-23T10:00:01Z", "/x/failed", DeleteMode::Trash, false),
            entry("r1", "2026-11-23T10:00:02Z", "/x/perm", DeleteMode::Permanent, true),
            admin,
            command,
            entry("r2", "2026-11-23T11:00:00Z", "/x/b", DeleteMode::Trash, true),
            entry("r3", "2026-11-23T12:00:00Z", "/x/c", DeleteMode::Permanent, true),
        ];
        let r1 = trashed_in_run(&entries, "r1");
        assert_eq!(r1, [Trashed { title: "/x/a".into(), path: "/x/a".into(), when: 1_795_428_000 }]);
        assert_eq!(last_trash_run(&entries).as_deref(), Some("r2"), "r3 moved nothing to the Trash");
        let mut newest_first = entries.clone();
        newest_first.reverse();
        assert_eq!(last_trash_run(&newest_first).as_deref(), Some("r2"), "order of the log does not matter");
        assert_eq!(last_trash_run(&[]), None);
    }

    #[test]
    fn restores_the_matching_entry_and_never_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().join("gone");
        let back_again = dir.path().join("back-again");
        std::fs::write(&back_again, b"new").expect("write");
        let missing = dir.path().join("emptied");
        let items = vec![
            Trashed { title: "gone".into(), path: gone.clone(), when: 1000 },
            Trashed { title: "back".into(), path: back_again.clone(), when: 1000 },
            Trashed { title: "emptied".into(), path: missing, when: 1000 },
        ];
        let store = FakeStore {
            entries: vec![
                trash_entry("old", &gone, 500),
                trash_entry("new", &gone, 1001),
                trash_entry("other", &back_again, 1002),
            ],
            ..FakeStore::default()
        };
        let outcomes: Vec<Restored> = restore(&items, &store).expect("list").into_iter().map(|(_, o)| o).collect();
        assert_eq!(outcomes, [Restored::Restored, Restored::PathExists, Restored::NotInTrash]);
        assert_eq!(*store.restored.borrow(), [gone], "only the entry from this run, nothing overwritten");
    }

    #[test]
    fn entries_older_than_the_run_are_not_restored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x");
        let items = [Trashed { title: "x".into(), path: path.clone(), when: 10_000 }];
        let store = FakeStore { entries: vec![trash_entry("older", &path, 10_000 - 3600)], ..FakeStore::default() };
        assert_eq!(restore(&items, &store).expect("list")[0].1, Restored::NotInTrash);
    }

    #[test]
    fn unsupported_store_is_an_error() {
        let store = FakeStore { unsupported: true, ..FakeStore::default() };
        let err = restore(&[], &store).unwrap_err();
        assert!(err.contains("drag the items back"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_store_explains_itself() {
        assert!(SystemTrashStore.list().unwrap_err().contains("Finder"));
        let e = trash_entry("x", Path::new("/x"), 0);
        assert!(SystemTrashStore.restore(&e).is_err());
    }

    /// Moves a file to the real freedesktop Trash and restores it. Touches the user's Trash, so it
    /// is opt-in: `cargo test -p diskdust-core --lib -- --ignored real_trash_round_trip`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "uses the real Trash"]
    fn real_trash_round_trip() {
        use crate::clean::{SystemTrash, Trasher};
        let home = dirs_home();
        let dir = tempfile::tempdir_in(&home).expect("tempdir in home");
        let file = dir.path().join(format!("diskdust-restore-check-{}", std::process::id()));
        std::fs::write(&file, b"restore me").expect("write");
        let when = OffsetDateTime::now_utc().unix_timestamp();
        SystemTrash.trash(&file).expect("trash");
        assert!(!file.exists());
        let items = [Trashed { title: "check".into(), path: file.clone(), when }];
        let outcome = restore(&items, &SystemTrashStore).expect("list");
        assert_eq!(outcome[0].1, Restored::Restored);
        assert_eq!(std::fs::read(&file).expect("restored"), b"restore me");
    }

    #[cfg(target_os = "linux")]
    fn dirs_home() -> PathBuf {
        std::env::var_os("HOME").map(PathBuf::from).expect("HOME")
    }
}
