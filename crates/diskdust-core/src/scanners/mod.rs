//! Scanners discover reclaimable items. Scanners only read; they never modify anything.

mod artifacts;
mod docker;
mod installers;
mod large_files;
mod orphans;
mod paths;
mod toolchains;
mod tools;
mod trash;
mod vms;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use thiserror::Error;

use crate::command::{CommandError, CommandRunner};
use crate::model::{Category, Finding, GENERIC, Os, Privilege, Risk};
use crate::size::{self, SizeReport};

pub use artifacts::BuildArtifactsScanner;
pub use docker::DockerScanner;
pub use installers::InstallersScanner;
pub use large_files::{LARGE_FILE_MIN, LargeFilesScanner};
pub use orphans::OrphanedAppDataScanner;
pub use paths::{Base, Mode, PathRule, PathRulesScanner, default_rules, resolved_rule_paths};
pub use toolchains::ToolchainsScanner;
pub use tools::{GoScanner, HomebrewScanner, JournalScanner, SimulatorScanner, SnapScanner, TimeMachineScanner};
pub use trash::TrashScanner;
pub use vms::VmDisksScanner;

/// Items smaller than this are not worth showing.
pub const MIN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("{0}")]
    Unavailable(String),
    #[error(transparent)]
    Command(#[from] CommandError),
}

/// Everything a scanner needs to know about the machine.
pub struct ScanContext<'a> {
    pub os: Os,
    pub home: PathBuf,
    /// Prefix for absolute system paths (`/` in production, a temp dir in tests).
    pub system_root: PathBuf,
    /// Folders searched for build artifacts.
    pub project_roots: Vec<PathBuf>,
    /// Folders containing installed `.app` bundles (macOS).
    pub app_dirs: Vec<PathBuf>,
    pub runner: &'a dyn CommandRunner,
    pub cancel: &'a AtomicBool,
}

impl std::fmt::Debug for ScanContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanContext")
            .field("os", &self.os)
            .field("home", &self.home)
            .field("system_root", &self.system_root)
            .field("project_roots", &self.project_roots)
            .finish_non_exhaustive()
    }
}

impl ScanContext<'_> {
    /// Resolves an absolute system path such as `/Library/Caches` under `system_root`.
    pub fn system_path(&self, absolute: &str) -> PathBuf {
        self.system_root.join(absolute.trim_start_matches('/'))
    }

    /// Measures `path`; `None` when the scan was cancelled mid-walk (the figures would be partial).
    pub fn measure(&self, path: &Path) -> Option<SizeReport> {
        let report = size::measure(path, self.cancel);
        report.complete.then_some(report)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Default project roots searched for build artifacts.
pub fn default_project_roots(home: &Path) -> Vec<PathBuf> {
    unique_dirs(
        [
            "Documents",
            "Projects",
            "projects",
            "Developer",
            "code",
            "Code",
            "dev",
            "src",
            "repos",
            "workspace",
            "work",
            "go/src",
        ]
        .iter()
        .map(|rel| home.join(rel)),
    )
}

/// Keeps existing real directories, dropping duplicates that refer to the same folder (e.g.
/// `code` and `Code` on case-insensitive file systems) and folders nested inside another entry.
pub fn unique_dirs(candidates: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let mut seen = std::collections::HashSet::new();
    let dirs: Vec<PathBuf> = candidates
        .into_iter()
        .filter_map(|p| {
            let meta = fs::metadata(&p).ok().filter(fs::Metadata::is_dir)?;
            seen.insert((meta.dev(), meta.ino())).then(|| p.canonicalize().unwrap_or(p))
        })
        .collect();
    dirs.iter().filter(|d| !dirs.iter().any(|other| other != *d && d.starts_with(other))).cloned().collect()
}

/// Default folders containing installed applications on macOS.
pub fn default_app_dirs(home: &Path) -> Vec<PathBuf> {
    vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/Applications/Utilities"),
        PathBuf::from("/System/Applications"),
        PathBuf::from("/System/Applications/Utilities"),
        home.join("Applications"),
    ]
}

/// A source of findings.
pub trait Scanner: Send + Sync {
    /// Stable identifier.
    fn id(&self) -> &'static str;
    /// Human-readable name shown while scanning.
    fn name(&self) -> &'static str;
    fn supports(&self, os: Os) -> bool;
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError>;
}

/// All built-in scanners.
pub fn default_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(PathRulesScanner::new(default_rules())),
        Box::new(DockerScanner),
        Box::new(HomebrewScanner),
        Box::new(GoScanner),
        Box::new(SimulatorScanner),
        Box::new(TrashScanner),
        Box::new(OrphanedAppDataScanner),
        Box::new(BuildArtifactsScanner),
        Box::new(ToolchainsScanner),
        Box::new(InstallersScanner),
        Box::new(VmDisksScanner),
        Box::new(TimeMachineScanner),
        Box::new(JournalScanner),
        Box::new(SnapScanner),
    ]
}

/// The built-in scanners plus the opt-in search for large files in the home folder.
pub fn scanners_for(large_files: bool) -> Vec<Box<dyn Scanner>> {
    let mut scanners = default_scanners();
    if large_files {
        scanners.push(Box::new(LargeFilesScanner::default()));
    }
    scanners
}

/// Appends a note when part of an item is hard-linked from elsewhere and is not freed by removing
/// it alone (e.g. `node_modules` installed by pnpm).
pub(crate) fn with_shared_note(detail: String, report: &SizeReport) -> String {
    if report.shared < MIN_BYTES {
        return detail;
    }
    format!(
        "{detail} Another {} is hard-linked from elsewhere (e.g. a package store) and is not freed by removing only this item.",
        crate::units::format_bytes(report.shared)
    )
}

/// Base finding with conservative defaults; callers override fields with struct update syntax.
pub(crate) fn base_finding(scanner: &str, id: String, category: Category, title: String) -> Finding {
    Finding {
        id,
        scanner: scanner.to_owned(),
        category,
        title,
        detail: String::new(),
        path: None,
        bytes: None,
        risk: Risk::Review,
        privilege: Privilege::User,
        action: None,
        specificity: GENERIC,
        last_modified: None,
        quit_first: None,
    }
}

/// Lists the non-symlink children of `dir`, sorted by name. Missing or unreadable → empty.
pub(crate) fn children(dir: &Path) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| !t.is_symlink()))
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// True when `path` exists and is a real directory (not a symlink to one).
pub(crate) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

pub(crate) fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use crate::command::fake::FakeRunner;

    pub struct Env {
        _dir: tempfile::TempDir,
        pub home: PathBuf,
        pub system: PathBuf,
        pub cancel: AtomicBool,
    }

    impl Env {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let base = dir.path().canonicalize().expect("canonical");
            let home = base.join("home");
            let system = base.join("sys");
            fs::create_dir_all(&home).expect("mkdir");
            fs::create_dir_all(&system).expect("mkdir");
            Self { _dir: dir, home, system, cancel: AtomicBool::new(false) }
        }

        pub fn ctx<'a>(&'a self, os: Os, runner: &'a FakeRunner) -> ScanContext<'a> {
            ScanContext {
                os,
                home: self.home.clone(),
                system_root: self.system.clone(),
                project_roots: vec![self.home.join("code")],
                app_dirs: vec![self.home.join("Applications")],
                runner,
                cancel: &self.cancel,
            }
        }

        /// Writes a file of `len` bytes at `rel` under home, creating parents.
        pub fn file(&self, rel: &str, len: usize) -> PathBuf {
            write_file(&self.home.join(rel), len)
        }

        pub fn sys_file(&self, rel: &str, len: usize) -> PathBuf {
            write_file(&self.system.join(rel), len)
        }
    }

    pub fn write_file(path: &Path, len: usize) -> PathBuf {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, vec![7u8; len]).expect("write");
        path.to_path_buf()
    }

    pub const BIG: usize = 2 * 1024 * 1024;

    pub fn sample_finding() -> Finding {
        base_finding("test", "test:item".to_owned(), Category::AppCaches, "Item".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn default_scanner_ids_are_unique() {
        let scanners = default_scanners();
        let mut ids: Vec<_> = scanners.iter().map(|s| s.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), scanners.len());
        assert!(scanners.iter().all(|s| !s.name().is_empty()));
    }

    #[test]
    fn children_skips_symlinks_and_sorts() {
        let env = Env::new();
        env.file("d/b", 1);
        env.file("d/a", 1);
        std::os::unix::fs::symlink(env.home.join("d/a"), env.home.join("d/c")).expect("symlink");
        let names: Vec<_> = children(&env.home.join("d")).iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(children(&env.home.join("missing")).is_empty());
    }

    #[test]
    fn default_roots_only_include_existing_dirs() {
        let env = Env::new();
        fs::create_dir_all(env.home.join("code")).expect("mkdir");
        assert_eq!(default_project_roots(&env.home).len(), 1);
        assert!(
            default_project_roots(&env.home)[0].ends_with("code")
                || default_project_roots(&env.home)[0].ends_with("Code")
        );
        assert!(default_app_dirs(&env.home).contains(&PathBuf::from("/Applications")));
    }

    #[test]
    fn unique_dirs_drops_duplicates_nested_and_missing() {
        let env = Env::new();
        fs::create_dir_all(env.home.join("a/b")).expect("mkdir");
        fs::create_dir_all(env.home.join("c")).expect("mkdir");
        std::os::unix::fs::symlink(env.home.join("c"), env.home.join("c-link")).expect("symlink");
        let out = unique_dirs([
            env.home.join("a"),
            env.home.join("a/b"),
            env.home.join("c"),
            env.home.join("c-link"),
            env.home.join("missing"),
        ]);
        assert_eq!(out, vec![env.home.join("a"), env.home.join("c")]);
    }

    #[test]
    fn shared_note_only_when_significant() {
        let small = SizeReport { shared: 10, ..SizeReport::default() };
        assert_eq!(with_shared_note("d.".into(), &small), "d.");
        let big = SizeReport { shared: 2_000_000, ..SizeReport::default() };
        assert!(with_shared_note("d.".into(), &big).contains("2.0 MB is hard-linked"));
    }

    #[test]
    fn context_helpers() {
        let env = Env::new();
        let runner = crate::command::fake::FakeRunner::new();
        let ctx = env.ctx(Os::Linux, &runner);
        assert_eq!(ctx.system_path("/var/cache"), env.system.join("var/cache"));
        assert!(!ctx.is_cancelled());
        assert!(ctx.measure(&env.home).is_some());
        ctx.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        env.file("sub/x", 1);
        assert!(ctx.measure(&env.home).is_none(), "cancelled walks are partial");
        assert!(format!("{ctx:?}").contains("ScanContext"));
        assert!(is_real_dir(&env.home));
        assert_eq!(file_name(Path::new("/")), "/");
    }
}
