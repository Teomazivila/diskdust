//! Large files anywhere in the home folder that no other rule explains (opt-in).
//!
//! Every result is `Review`: these are the user's own files. The walk stays out of places where
//! deleting a single file breaks something bigger: hidden folders (app-managed data such as VM
//! disks), `.git`, `~/Library`, the Trash, and macOS packages or libraries (`.photoslibrary`,
//! `.sparsebundle`, VM bundles, …). Results have the lowest specificity, so a large file inside
//! something another scanner already reports is dropped by the overlap de-duplication.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use rayon::prelude::*;

use super::{ScanContext, ScanError, Scanner, base_finding};
use crate::model::{Category, CleanupAction, Finding, LOWEST, Os};
use crate::size::allocated_bytes;

/// Files smaller than this are not reported.
pub const LARGE_FILE_MIN: u64 = 1_000_000_000;

/// Folder extensions that are single documents or libraries: never look inside them.
const PACKAGE_EXTENSIONS: &[&str] = &[
    "app",
    "aplibrary",
    "band",
    "bundle",
    "dtBase2",
    "fcpbundle",
    "framework",
    "imovielibrary",
    "logicx",
    "lrdata",
    "musiclibrary",
    "photolibrary",
    "photoslibrary",
    "pvm",
    "sparsebundle",
    "tvlibrary",
    "utm",
    "vmwarevm",
    "xcarchive",
];

#[derive(Debug, Clone, Copy)]
pub struct LargeFilesScanner {
    /// Smallest allocated size reported.
    pub min_bytes: u64,
}

impl Default for LargeFilesScanner {
    fn default() -> Self {
        Self { min_bytes: LARGE_FILE_MIN }
    }
}

/// Top-level folders of the home directory that are never searched.
fn excluded_top_level(os: Os) -> &'static [&'static str] {
    match os {
        Os::MacOs => &["Library"],
        Os::Linux => &["snap"],
    }
}

fn is_package(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|e| {
        let e = e.to_string_lossy();
        PACKAGE_EXTENSIONS.iter().any(|p| p.eq_ignore_ascii_case(&e))
    })
}

/// Whether the walk may descend into the folder `name`.
fn searchable(name: &str) -> bool {
    !name.starts_with('.') && !is_package(name)
}

struct Walk<'a> {
    device: u64,
    min_bytes: u64,
    ctx: &'a ScanContext<'a>,
}

impl Walk<'_> {
    fn dir(&self, dir: &Path) -> Vec<(PathBuf, fs::Metadata)> {
        if self.ctx.is_cancelled() {
            return Vec::new();
        }
        let Ok(read) = fs::read_dir(dir) else { return Vec::new() };
        let entries: Vec<PathBuf> = read.filter_map(Result::ok).map(|e| e.path()).collect();
        entries
            .par_iter()
            .flat_map(|path| {
                let Ok(meta) = fs::symlink_metadata(path) else { return Vec::new() };
                let name = path.file_name().map_or_default(|n| n.to_string_lossy().into_owned());
                if meta.file_type().is_symlink() {
                    Vec::new()
                } else if meta.is_dir() {
                    if meta.dev() == self.device && searchable(&name) { self.dir(path) } else { Vec::new() }
                } else if meta.is_file() && !name.starts_with('.') && allocated_bytes(&meta) >= self.min_bytes {
                    vec![(path.clone(), meta)]
                } else {
                    Vec::new()
                }
            })
            .collect()
    }
}

impl Scanner for LargeFilesScanner {
    fn id(&self) -> &'static str {
        "large-files"
    }

    fn name(&self) -> &'static str {
        "Large files in your home folder"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Ok(home_meta) = fs::symlink_metadata(&ctx.home) else { return Ok(Vec::new()) };
        let walk = Walk { device: home_meta.dev(), min_bytes: self.min_bytes, ctx };
        let excluded = excluded_top_level(ctx.os);
        let Ok(read) = fs::read_dir(&ctx.home) else { return Ok(Vec::new()) };
        let top: Vec<PathBuf> = read
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().map_or_default(|n| n.to_string_lossy().into_owned());
                !excluded.contains(&name.as_str()) && searchable(&name)
            })
            .collect();
        let files: Vec<(PathBuf, fs::Metadata)> = top
            .par_iter()
            .flat_map(|path| match fs::symlink_metadata(path) {
                Ok(m) if m.is_dir() && m.dev() == walk.device => walk.dir(path),
                Ok(m) if m.is_file() && allocated_bytes(&m) >= self.min_bytes => vec![(path.clone(), m)],
                _ => Vec::new(),
            })
            .collect();
        if ctx.is_cancelled() {
            return Ok(Vec::new());
        }
        Ok(files
            .into_iter()
            .map(|(path, meta)| {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .and_then(|d| i64::try_from(d.as_secs()).ok());
                let title = path.file_name().map_or_default(|n| n.to_string_lossy().into_owned());
                Finding {
                    detail: "Large file in your home folder that no other rule explains. Check that you no longer \
                             need it; it is moved to the Trash unless you delete permanently."
                        .to_owned(),
                    path: Some(path.clone()),
                    bytes: Some(allocated_bytes(&meta)),
                    last_modified: modified,
                    action: Some(CleanupAction::RemovePath { path: path.clone(), root: ctx.home.clone() }),
                    specificity: LOWEST,
                    ..base_finding(
                        "large-files",
                        format!("large-files:{}", path.display()),
                        Category::LargeFiles,
                        title,
                    )
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::model::Risk;
    use crate::scanners::testutil::Env;
    use std::fs::File;

    /// Threshold used by the tests, so they write megabytes rather than gigabytes.
    const TEST_MIN: u64 = 4 * 1024 * 1024;

    fn scanner() -> LargeFilesScanner {
        LargeFilesScanner { min_bytes: TEST_MIN }
    }

    /// A file with `TEST_MIN` really allocated bytes.
    fn big_file(env: &Env, rel: &str) -> PathBuf {
        let path = env.home.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, vec![1u8; usize::try_from(TEST_MIN).expect("fits")]).expect("write");
        path
    }

    #[test]
    fn package_and_hidden_rules() {
        assert!(searchable("Movies"));
        assert!(!searchable(".lima"));
        assert!(!searchable("Photos Library.photoslibrary"));
        assert!(!searchable("Backup.SparseBundle"), "case-insensitive");
        assert!(!searchable("Windows 11.pvm"));
        assert!(searchable("archive.tar"));
    }

    #[test]
    fn finds_large_files_outside_excluded_places() {
        let env = Env::new();
        let movie = big_file(&env, "Movies/holiday.mov");
        big_file(&env, ".lima/default/diffdisk");
        big_file(&env, "Pictures/Photos Library.photoslibrary/originals/a.heic");
        big_file(&env, "Library/Containers/x/huge.bin");
        big_file(&env, "code/repo/.git/objects/pack/pack-1.pack");
        fs::write(env.home.join("Movies/small.mov"), vec![0u8; 1024]).expect("small");
        let sparse = File::create(env.home.join("Movies/sparse.img")).expect("create");
        sparse.set_len(TEST_MIN * 100).expect("sparse");

        let runner = FakeRunner::new();
        let found = scanner().scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        let paths: Vec<_> = found.iter().filter_map(|f| f.path.clone()).collect();
        assert_eq!(
            paths,
            std::slice::from_ref(&movie),
            "only the movie; sparse, hidden, package, Library, .git skipped"
        );
        let f = &found[0];
        assert_eq!(f.risk, Risk::Review);
        assert_eq!(f.category, Category::LargeFiles);
        assert_eq!(f.specificity, LOWEST);
        assert_eq!(f.action, Some(CleanupAction::RemovePath { path: movie, root: env.home.clone() }));
        assert!(f.last_modified.is_some());
    }

    #[test]
    fn cancelled_scan_reports_nothing_and_metadata() {
        let env = Env::new();
        big_file(&env, "Downloads/disk.img");
        env.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let runner = FakeRunner::new();
        assert!(scanner().scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
        assert_eq!(scanner().id(), "large-files");
        assert!(scanner().supports(Os::Linux) && !scanner().name().is_empty());
        assert_eq!(LargeFilesScanner::default().min_bytes, LARGE_FILE_MIN);
        assert_eq!(excluded_top_level(Os::Linux), ["snap"]);
    }
}
