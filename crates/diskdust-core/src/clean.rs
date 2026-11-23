//! Executes cleanup actions. Every path is re-validated immediately before it is touched.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::command::{CommandError, CommandRunner};
use crate::model::{CleanupAction, Finding, KnownCommand, RunningApp};
use crate::safety::{SafetyError, SafetyPolicy};

/// Prune commands on large Docker installs can take a while.
const COMMAND_TIMEOUT: Duration = Duration::from_mins(30);

/// What to do with removed paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteMode {
    /// Move to the OS Trash (recoverable; space is reclaimed when the Trash is emptied).
    Trash,
    /// Delete immediately.
    Permanent,
}

#[derive(Debug, Error)]
pub enum CleanError {
    #[error(transparent)]
    Safety(#[from] SafetyError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error("`{program}` failed: {detail}")]
    CommandFailed { program: String, detail: String },
    #[error("this action requires administrator privileges")]
    RequiresAdmin,
    #[error("refusing malformed command")]
    Malformed,
    #[error("could not remove {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not move {path} to Trash: {message}")]
    Trash { path: PathBuf, message: String },
    #[error("removed {removed} of {total} items; first error: {first_error}")]
    Partial { removed: usize, total: usize, first_error: String },
}

/// Moves paths to the OS Trash.
pub trait Trasher: Send + Sync {
    fn trash(&self, path: &Path) -> Result<(), String>;
}

/// [`Trasher`] backed by the platform Trash (Finder-compatible on macOS, freedesktop on Linux).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTrash;

impl Trasher for SystemTrash {
    fn trash(&self, path: &Path) -> Result<(), String> {
        #[allow(unused_mut)]
        let mut ctx = trash::TrashContext::new();
        #[cfg(target_os = "macos")]
        {
            use trash::macos::{DeleteMethod, TrashContextExtMacos};
            // NSFileManager avoids scripting Finder (no Automation permission prompt).
            ctx.set_delete_method(DeleteMethod::NsFileManager);
        }
        ctx.delete(path).map_err(|e| e.to_string())
    }
}

/// Executes [`CleanupAction`]s.
pub struct Cleaner<'a> {
    pub policy: &'a SafetyPolicy,
    pub runner: &'a dyn CommandRunner,
    pub trasher: &'a dyn Trasher,
    pub mode: DeleteMode,
    /// Whether admin-only commands may run (true only inside the privileged helper).
    pub allow_admin: bool,
}

impl std::fmt::Debug for Cleaner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cleaner")
            .field("mode", &self.mode)
            .field("allow_admin", &self.allow_admin)
            .finish_non_exhaustive()
    }
}

impl Cleaner<'_> {
    /// Privileged cleaners (the root helper) never change permissions; see [`Repair`].
    const fn repair(&self) -> Repair {
        if self.allow_admin { Repair::Never } else { Repair::MakeWritable }
    }

    /// Executes one action, returning a short human summary on success.
    pub fn execute(&self, action: &CleanupAction) -> Result<String, CleanError> {
        match action {
            CleanupAction::RemovePath { path, root } => {
                let target = self.policy.validate(path, root)?;
                match self.mode {
                    DeleteMode::Trash => {
                        self.trasher
                            .trash(&target)
                            .map_err(|message| CleanError::Trash { path: target.clone(), message })?;
                        Ok("Moved to Trash".to_owned())
                    }
                    DeleteMode::Permanent => {
                        remove(&target, self.repair())?;
                        Ok("Deleted".to_owned())
                    }
                }
            }
            CleanupAction::EmptyDir { path, root } => self.empty_dir(path, root),
            CleanupAction::Run(cmd) => self.run(cmd),
        }
    }

    fn empty_dir(&self, path: &Path, root: &Path) -> Result<String, CleanError> {
        let dir = self.policy.validate(path, root)?;
        let entries: Vec<PathBuf> = fs::read_dir(&dir)
            .map_err(|source| CleanError::Io { path: dir.clone(), source })?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        let total = entries.len();
        let mut removed = 0;
        let mut first_error = None;
        for entry in entries {
            // Symlinks inside the folder are removed as links (never followed).
            let result = match fs::symlink_metadata(&entry) {
                Ok(m) if m.file_type().is_symlink() => {
                    fs::remove_file(&entry).map_err(|source| CleanError::Io { path: entry.clone(), source })
                }
                _ => {
                    self.policy.validate(&entry, &dir).map_err(CleanError::from).and_then(|p| remove(&p, self.repair()))
                }
            };
            match result {
                Ok(()) => removed += 1,
                Err(e) => {
                    first_error.get_or_insert_with(|| e.to_string());
                }
            }
        }
        match first_error {
            None => Ok(format!("Removed {removed} items")),
            Some(first_error) => Err(CleanError::Partial { removed, total, first_error }),
        }
    }

    fn run(&self, cmd: &KnownCommand) -> Result<String, CleanError> {
        if !cmd.is_well_formed() {
            return Err(CleanError::Malformed);
        }
        if cmd.requires_admin() && !self.allow_admin {
            return Err(CleanError::RequiresAdmin);
        }
        let argv = cmd.argv();
        let out = self.runner.run(&argv, COMMAND_TIMEOUT)?;
        if !out.success {
            let detail = if out.stderr.trim().is_empty() { &out.stdout } else { &out.stderr };
            return Err(CleanError::CommandFailed { program: argv[0].clone(), detail: tail(detail, 300) });
        }
        let summary = out.stdout.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("Done");
        Ok(tail(summary, 200))
    }
}

/// Whether an app is running, according to `pgrep`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    Running,
    NotRunning,
    /// `pgrep` is missing, timed out or failed: treated as "maybe running" (fail closed).
    Unknown(String),
}

/// Checks `app` with `pgrep`, which exits 0 when a process matched and 1 when none did; any
/// other outcome is [`RunState::Unknown`].
pub fn run_state(runner: &dyn CommandRunner, app: &RunningApp) -> RunState {
    let argv: Vec<String> = std::iter::once("pgrep".to_owned()).chain(app.pgrep.iter().cloned()).collect();
    match runner.run(&argv, Duration::from_secs(5)) {
        Ok(out) if out.success => RunState::Running,
        Ok(out) if out.code == Some(1) => RunState::NotRunning,
        Ok(out) => RunState::Unknown(format!("pgrep exited with {:?}: {}", out.code, out.stderr.trim())),
        Err(e) => RunState::Unknown(e.to_string()),
    }
}

/// Reason to skip `finding` because the app owning its data is (or may be) running, if any.
pub fn quit_first_reason(runner: &dyn CommandRunner, finding: &Finding) -> Option<String> {
    let app = finding.quit_first.as_ref()?;
    match run_state(runner, app) {
        RunState::NotRunning => None,
        RunState::Running => Some(format!("{} is running. Quit it, then clean again.", app.app)),
        RunState::Unknown(why) => {
            tracing::warn!(app = %app.app, error = %why, "could not check whether the app is running");
            Some(format!("Could not check whether {} is running ({why}). Quit it, then clean again.", app.app))
        }
    }
}

/// Last `max` characters of `text`, trimmed.
fn tail(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    let count = trimmed.chars().count();
    if count <= max {
        trimmed.to_owned()
    } else {
        format!("…{}", trimmed.chars().skip(count - max).collect::<String>())
    }
}

/// Whether [`remove`] may make read-only directories writable and retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Repair {
    /// User process: read-only folders such as Go module caches are made writable and retried.
    /// A same-user race on the path gains nothing the user could not already do.
    MakeWritable,
    /// Privileged helper: never change permissions. `set_permissions` follows symlinks, so a
    /// path swapped for a symlink between the check and the chmod would make an arbitrary file
    /// (e.g. `/etc/sudoers`) writable as root. Root does not need it to delete anyway.
    Never,
}

/// Permanently removes a validated path; see [`Repair`] for read-only directories.
fn remove(path: &Path, repair: Repair) -> Result<(), CleanError> {
    let io_err = |source| CleanError::Io { path: path.to_path_buf(), source };
    let meta = fs::symlink_metadata(path).map_err(io_err)?;
    if !meta.is_dir() {
        return fs::remove_file(path).map_err(io_err);
    }
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && repair == Repair::MakeWritable => {
            make_dirs_writable(path);
            fs::remove_dir_all(path).map_err(io_err)
        }
        other => other.map_err(io_err),
    }
}

fn make_dirs_writable(dir: &Path) {
    let Ok(meta) = fs::symlink_metadata(dir) else { return };
    if !meta.is_dir() {
        return;
    }
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() | 0o700);
    let _ = fs::set_permissions(dir, perms);
    if let Ok(read) = fs::read_dir(dir) {
        for entry in read.filter_map(Result::ok) {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                make_dirs_writable(&entry.path());
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::write_file;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    pub(crate) struct RecordingTrash {
        pub trashed: Mutex<Vec<PathBuf>>,
        pub fail: bool,
    }

    impl Trasher for RecordingTrash {
        fn trash(&self, path: &Path) -> Result<(), String> {
            if self.fail {
                return Err("trash unavailable".into());
            }
            self.trashed.lock().expect("lock").push(path.to_path_buf());
            fs::remove_dir_all(path).map_err(|e| e.to_string())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        policy: SafetyPolicy,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical").join("cache");
        write_file(&root.join("app/blob"), 100);
        Fixture { _dir: dir, root, policy: SafetyPolicy::new(Vec::new()) }
    }

    fn cleaner<'a>(f: &'a Fixture, runner: &'a FakeRunner, trash: &'a RecordingTrash, mode: DeleteMode) -> Cleaner<'a> {
        Cleaner { policy: &f.policy, runner, trasher: trash, mode, allow_admin: false }
    }

    #[test]
    fn remove_path_to_trash() {
        let f = fixture();
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let action = CleanupAction::RemovePath { path: f.root.join("app"), root: f.root.clone() };
        let msg = cleaner(&f, &runner, &trash, DeleteMode::Trash).execute(&action).expect("ok");
        assert_eq!(msg, "Moved to Trash");
        assert_eq!(*trash.trashed.lock().expect("lock"), vec![f.root.join("app")]);
    }

    #[test]
    fn trash_failure_is_reported() {
        let f = fixture();
        let (runner, trash) = (FakeRunner::new(), RecordingTrash { fail: true, ..Default::default() });
        let action = CleanupAction::RemovePath { path: f.root.join("app"), root: f.root.clone() };
        let err = cleaner(&f, &runner, &trash, DeleteMode::Trash).execute(&action).unwrap_err();
        assert!(matches!(err, CleanError::Trash { .. }));
        assert!(f.root.join("app").exists());
    }

    #[test]
    fn remove_path_permanently_including_read_only_dirs() {
        let f = fixture();
        let ro = f.root.join("app/readonly");
        write_file(&ro.join("f"), 10);
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).expect("chmod");
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let action = CleanupAction::RemovePath { path: f.root.join("app"), root: f.root.clone() };
        assert_eq!(cleaner(&f, &runner, &trash, DeleteMode::Permanent).execute(&action).expect("ok"), "Deleted");
        assert!(!f.root.join("app").exists());
        assert!(trash.trashed.lock().expect("lock").is_empty());
    }

    #[test]
    fn privileged_cleaner_never_changes_permissions() {
        let f = fixture();
        let ro = f.root.join("app/readonly");
        write_file(&ro.join("f"), 10);
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).expect("chmod");
        let is_root = fs::write(ro.join("probe"), b"x").is_ok();
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let helper = Cleaner { allow_admin: true, ..cleaner(&f, &runner, &trash, DeleteMode::Permanent) };
        let result = helper.execute(&CleanupAction::RemovePath { path: f.root.join("app"), root: f.root.clone() });
        if is_root {
            // Root deletes read-only folders without touching permissions.
            assert!(result.is_ok());
            return;
        }
        assert!(matches!(result, Err(CleanError::Io { .. })), "{result:?}");
        let mode = fs::metadata(&ro).expect("still there").permissions().mode() & 0o777;
        assert_eq!(mode, 0o555, "the helper must not chmod");
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).expect("cleanup");
    }

    #[test]
    fn remove_single_file() {
        let f = fixture();
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let action = CleanupAction::RemovePath { path: f.root.join("app/blob"), root: f.root.clone() };
        cleaner(&f, &runner, &trash, DeleteMode::Permanent).execute(&action).expect("ok");
        assert!(!f.root.join("app/blob").exists());
    }

    #[test]
    fn unsafe_paths_are_refused() {
        let f = fixture();
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let c = cleaner(&f, &runner, &trash, DeleteMode::Permanent);
        let err = c.execute(&CleanupAction::RemovePath { path: f.root.clone(), root: f.root.clone() }).unwrap_err();
        assert!(matches!(err, CleanError::Safety(SafetyError::OutsideRoot { .. })));
        assert!(f.root.exists());
    }

    #[test]
    fn empty_dir_removes_children_but_keeps_dir_and_link_targets() {
        let f = fixture();
        let trash_dir = f.root.join("Trash");
        write_file(&trash_dir.join("files/a"), 10);
        write_file(&trash_dir.join("b"), 10);
        std::os::unix::fs::symlink(f.root.join("app"), trash_dir.join("link")).expect("symlink");
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let msg = cleaner(&f, &runner, &trash, DeleteMode::Trash)
            .execute(&CleanupAction::EmptyDir { path: trash_dir.clone(), root: f.root.clone() })
            .expect("ok");
        assert_eq!(msg, "Removed 3 items");
        assert!(trash_dir.is_dir());
        assert_eq!(fs::read_dir(&trash_dir).expect("read").count(), 0);
        assert!(f.root.join("app/blob").exists(), "symlink target must survive");
    }

    #[test]
    fn empty_dir_reports_partial_failure() {
        let f = fixture();
        let trash_dir = f.root.join("Trash");
        write_file(&trash_dir.join("a"), 10);
        write_file(&trash_dir.join("b/c"), 10);
        fs::set_permissions(&trash_dir, fs::Permissions::from_mode(0o555)).expect("chmod");
        let is_root = fs::write(trash_dir.join("probe"), b"x").is_ok();
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let result = cleaner(&f, &runner, &trash, DeleteMode::Permanent)
            .execute(&CleanupAction::EmptyDir { path: trash_dir.clone(), root: f.root.clone() });
        fs::set_permissions(&trash_dir, fs::Permissions::from_mode(0o755)).expect("chmod back");
        // Root ignores permission bits (e.g. CI containers); the failure path only exists for users.
        if !is_root {
            let err = result.unwrap_err();
            assert!(matches!(err, CleanError::Partial { removed: 0, total: 2, .. }), "{err}");
        }
    }

    #[test]
    fn empty_dir_refuses_folder_containing_protected_path() {
        let f = fixture();
        let trash_dir = f.root.join("Trash");
        write_file(&trash_dir.join("protected/x"), 10);
        let policy = SafetyPolicy::new([trash_dir.join("protected")]);
        let (runner, trash) = (FakeRunner::new(), RecordingTrash::default());
        let c = Cleaner {
            policy: &policy,
            runner: &runner,
            trasher: &trash,
            mode: DeleteMode::Permanent,
            allow_admin: false,
        };
        let err = c.execute(&CleanupAction::EmptyDir { path: trash_dir.clone(), root: f.root.clone() }).unwrap_err();
        assert!(matches!(err, CleanError::Safety(SafetyError::Protected(_))), "{err}");
        assert!(trash_dir.join("protected/x").exists());
    }

    #[test]
    fn commands_run_and_report() {
        let f = fixture();
        let runner = FakeRunner::new().respond(
            "docker builder prune --all --force",
            true,
            "ID\tRECLAIMABLE\nabc\t1GB\nTotal:\t12.85GB\n\n",
        );
        let trash = RecordingTrash::default();
        let msg = cleaner(&f, &runner, &trash, DeleteMode::Trash)
            .execute(&CleanupAction::Run(KnownCommand::DockerPruneBuildCache))
            .expect("ok");
        assert_eq!(msg, "Total:\t12.85GB");
    }

    #[test]
    fn failing_command_includes_stderr() {
        let f = fixture();
        let runner = FakeRunner::new().respond("brew cleanup --prune=all", false, "boom on stdout");
        let trash = RecordingTrash::default();
        let err = cleaner(&f, &runner, &trash, DeleteMode::Trash)
            .execute(&CleanupAction::Run(KnownCommand::BrewCleanup))
            .unwrap_err();
        assert!(err.to_string().contains("boom on stdout"), "{err}");
    }

    #[test]
    fn admin_and_malformed_commands_are_refused_without_running() {
        let f = fixture();
        let runner = FakeRunner::new().installed("apt-get").installed("snap");
        let trash = RecordingTrash::default();
        let c = cleaner(&f, &runner, &trash, DeleteMode::Trash);
        assert!(matches!(c.execute(&CleanupAction::Run(KnownCommand::AptClean)), Err(CleanError::RequiresAdmin)));
        let bad = KnownCommand::SnapRemoveRevision { name: "--x".into(), revision: "1".into() };
        assert!(matches!(c.execute(&CleanupAction::Run(bad)), Err(CleanError::Malformed)));
        assert!(runner.calls.lock().expect("lock").is_empty());
        let admin = Cleaner { allow_admin: true, ..c };
        assert!(admin.execute(&CleanupAction::Run(KnownCommand::AptClean)).is_ok());
        assert!(format!("{admin:?}").contains("allow_admin: true"));
    }

    /// Exercises the real platform Trash (`NSFileManager` on macOS, freedesktop on Linux) with a
    /// disposable file. Ignored by default because it leaves that file in the user's Trash:
    /// `cargo test -p diskdust-core -- --ignored system_trash`.
    #[test]
    #[ignore = "moves a disposable file into the user's real Trash"]
    fn system_trash_moves_a_real_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join(format!("diskdust-trash-check-{}.txt", std::process::id()));
        fs::write(&file, b"diskdust Trash verification; safe to delete").expect("write");
        SystemTrash.trash(&file).expect("moved to Trash");
        assert!(!file.exists(), "file must leave its folder");
    }

    #[test]
    fn running_apps_block_their_items() {
        let slack = RunningApp { app: "Slack".into(), pgrep: vec!["-f".into(), "Slack.app/Contents/MacOS/".into()] };
        let mut finding = crate::scanners::testutil::sample_finding();
        assert_eq!(quit_first_reason(&FakeRunner::new(), &finding), None, "no app attached");
        finding.quit_first = Some(slack.clone());
        let running = FakeRunner::new().respond("pgrep -f Slack.app/Contents/MacOS/", true, "123\n");
        assert_eq!(
            quit_first_reason(&running, &finding).as_deref(),
            Some("Slack is running. Quit it, then clean again.")
        );
        let stopped = FakeRunner::new().respond("pgrep -f Slack.app/Contents/MacOS/", false, "");
        assert!(quit_first_reason(&stopped, &finding).is_none());
        assert_eq!(run_state(&stopped, &slack), RunState::NotRunning);
    }

    #[test]
    fn running_app_check_fails_closed() {
        let slack = RunningApp { app: "Slack".into(), pgrep: vec!["-f".into(), "Slack.app/Contents/MacOS/".into()] };
        let mut finding = crate::scanners::testutil::sample_finding();
        finding.quit_first = Some(slack.clone());
        let missing = FakeRunner::new();
        assert!(matches!(run_state(&missing, &slack), RunState::Unknown(_)), "missing pgrep");
        for code in [2, 3] {
            let broken = FakeRunner::new().respond_code("pgrep -f Slack.app/Contents/MacOS/", code, "");
            assert!(matches!(run_state(&broken, &slack), RunState::Unknown(_)), "exit {code}");
            let reason = quit_first_reason(&broken, &finding).expect("blocked");
            assert!(reason.starts_with("Could not check whether Slack is running"), "{reason}");
        }
    }

    #[test]
    fn tail_truncates_by_chars() {
        assert_eq!(tail("  short  ", 10), "short");
        assert_eq!(tail("abcdefé", 3), "…efé");
    }
}
