//! Identical files in Downloads: every copy but one is offered for removal.
//!
//! Files are grouped by size, pre-filtered by a hash of their first and last 64 KiB, and confirmed
//! byte for byte. The oldest copy is kept. Each other copy is offered with
//! [`CleanupAction::RemoveDuplicate`], which re-checks at clean time that the kept copy still
//! exists and is identical, so a clean can never remove the last copy (duplicates also run last).

use std::collections::HashMap;
use std::fs::{self, File};
use std::hash::{DefaultHasher, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding};
use crate::model::{Category, CleanupAction, Finding, Os, Risk, SPECIFIC};
use crate::size::allocated_bytes;

/// Bytes hashed at each end of a file for the cheap pre-filter.
const EDGE: u64 = 64 * 1024;

#[derive(Debug)]
pub struct DuplicatesScanner;

/// Files in `dir` (recursively), skipping hidden entries, symlinks and other file systems.
fn files(dir: &Path, device: u64, ctx: &ScanContext<'_>, out: &mut Vec<(PathBuf, fs::Metadata)>) {
    let Ok(read) = fs::read_dir(dir) else { return };
    for entry in read.filter_map(Result::ok) {
        if ctx.is_cancelled() {
            return;
        }
        let path = entry.path();
        if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if meta.is_dir() && meta.dev() == device && path.extension().is_none_or(|e| e != "app") {
            files(&path, device, ctx, out);
        } else if meta.is_file() && meta.len() >= MIN_BYTES {
            out.push((path, meta));
        }
    }
}

/// Hash of the first and last [`EDGE`] bytes (the whole file when smaller).
fn edge_hash(path: &Path, len: u64) -> io::Result<u64> {
    let mut file = File::open(path)?;
    let mut hasher = DefaultHasher::new();
    let mut buf = vec![0u8; usize::try_from(EDGE.min(len)).unwrap_or(0)];
    file.read_exact(&mut buf)?;
    hasher.write(&buf);
    if len > EDGE {
        file.seek(SeekFrom::Start(len - EDGE.min(len)))?;
        file.read_exact(&mut buf)?;
        hasher.write(&buf);
    }
    Ok(hasher.finish())
}

/// Whether two files have identical contents, compared in chunks.
pub fn same_contents(a: &Path, b: &Path) -> io::Result<bool> {
    let (mut fa, mut fb) = (File::open(a)?, File::open(b)?);
    if fa.metadata()?.len() != fb.metadata()?.len() {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = fa.read(&mut ba)?;
        if n == 0 {
            return Ok(fb.read(&mut bb[..1])? == 0);
        }
        fb.read_exact(&mut bb[..n])?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
    }
}

fn modified(meta: &fs::Metadata) -> Option<i64> {
    meta.modified().ok()?.duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_secs()).ok())
}

/// Splits candidates (same size and edge hash) into groups of identical files.
fn identical_groups(mut candidates: Vec<(PathBuf, fs::Metadata)>) -> Vec<Vec<(PathBuf, fs::Metadata)>> {
    let mut groups: Vec<Vec<(PathBuf, fs::Metadata)>> = Vec::new();
    // Oldest first, then path: the first member of each group is the copy that is kept.
    candidates.sort_by(|a, b| modified(&a.1).cmp(&modified(&b.1)).then_with(|| a.0.cmp(&b.0)));
    for (path, meta) in candidates {
        let home = groups.iter_mut().find(|g| same_contents(&g[0].0, &path).unwrap_or(false));
        match home {
            Some(group) => group.push((path, meta)),
            None => groups.push(vec![(path, meta)]),
        }
    }
    groups.into_iter().filter(|g| g.len() > 1).collect()
}

fn downloads(ctx: &ScanContext<'_>) -> PathBuf {
    ctx.home.join("Downloads")
}

impl Scanner for DuplicatesScanner {
    fn id(&self) -> &'static str {
        "duplicates"
    }

    fn name(&self) -> &'static str {
        "Duplicate files in Downloads"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let root = downloads(ctx);
        let Ok(meta) = fs::symlink_metadata(&root) else { return Ok(Vec::new()) };
        if !meta.is_dir() {
            return Ok(Vec::new());
        }
        let mut all = Vec::new();
        files(&root, meta.dev(), ctx, &mut all);
        let mut by_key: HashMap<(u64, u64), Vec<(PathBuf, fs::Metadata)>> = HashMap::new();
        let mut by_size: HashMap<u64, Vec<(PathBuf, fs::Metadata)>> = HashMap::new();
        for (path, meta) in all {
            by_size.entry(meta.len()).or_default().push((path, meta));
        }
        for (len, same_size) in by_size.into_iter().filter(|(_, v)| v.len() > 1) {
            for (path, meta) in same_size {
                if let Ok(h) = edge_hash(&path, len) {
                    by_key.entry((len, h)).or_default().push((path, meta));
                }
            }
        }
        let mut found = Vec::new();
        for candidates in by_key.into_values().filter(|v| v.len() > 1) {
            if ctx.is_cancelled() {
                return Ok(Vec::new());
            }
            for group in identical_groups(candidates) {
                let (keep, _) = &group[0];
                for (copy, meta) in &group[1..] {
                    let name = copy.file_name().map_or_default(|n| n.to_string_lossy().into_owned());
                    found.push(Finding {
                        detail: format!(
                            "Same contents as {}, which is kept. Checked again just before removal.",
                            keep.display()
                        ),
                        path: Some(copy.clone()),
                        bytes: Some(allocated_bytes(meta)),
                        last_modified: modified(meta),
                        risk: Risk::Safe,
                        action: Some(CleanupAction::RemoveDuplicate {
                            path: copy.clone(),
                            root: root.clone(),
                            original: keep.clone(),
                        }),
                        specificity: SPECIFIC,
                        ..base_finding(
                            "duplicates",
                            format!("duplicates:{}", copy.display()),
                            Category::Duplicates,
                            format!("{name} (duplicate)"),
                        )
                    });
                }
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::Env;
    use std::time::{Duration, SystemTime};

    fn write(env: &Env, rel: &str, contents: &[u8], age_days: u64) -> PathBuf {
        let path = env.home.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, contents).expect("write");
        let when = SystemTime::now() - Duration::from_secs(age_days * 86_400);
        File::options().write(true).open(&path).expect("open").set_modified(when).expect("mtime");
        path
    }

    fn blob(seed: u8) -> Vec<u8> {
        (0..2 * 1024 * 1024).map(|i: u32| (i % 251) as u8 ^ seed).collect()
    }

    #[test]
    fn keeps_the_oldest_copy_and_offers_the_others() {
        let env = Env::new();
        let kept = write(&env, "Downloads/report.pdf", &blob(1), 30);
        let copy1 = write(&env, "Downloads/report (1).pdf", &blob(1), 10);
        let copy2 = write(&env, "Downloads/old/report.pdf", &blob(1), 5);
        write(&env, "Downloads/other.pdf", &blob(2), 1);
        let mut same_edges = blob(1);
        same_edges[1024 * 1024] ^= 0xff; // same size, same first/last 64 KiB, different middle
        write(&env, "Downloads/almost.pdf", &same_edges, 1);
        write(&env, "Downloads/.hidden.pdf", &blob(1), 1);
        let runner = FakeRunner::new();
        let mut found = DuplicatesScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        found.sort_by(|a, b| a.path.cmp(&b.path));
        let copies: Vec<_> = found.iter().filter_map(|f| f.path.clone()).collect();
        let mut expected = vec![copy1, copy2];
        expected.sort();
        assert_eq!(copies, expected, "the near-identical and hidden files are not duplicates");
        for f in &found {
            assert_eq!(f.risk, Risk::Safe);
            assert!(
                matches!(&f.action, Some(CleanupAction::RemoveDuplicate { original, .. }) if *original == kept),
                "the oldest copy is the one kept: {:?}",
                f.action
            );
            assert!(f.title.ends_with("(duplicate)"));
        }
    }

    #[test]
    fn same_contents_compares_every_byte() {
        let env = Env::new();
        let a = write(&env, "a", &blob(1), 0);
        let b = write(&env, "b", &blob(1), 0);
        let mut changed = blob(1);
        changed[123_456] ^= 1;
        let c = write(&env, "c", &changed, 0);
        let d = write(&env, "d", &blob(1)[..1000], 0);
        assert!(same_contents(&a, &b).expect("io"));
        assert!(!same_contents(&a, &c).expect("io"));
        assert!(!same_contents(&a, &d).expect("io"));
        assert!(same_contents(&a, &env.home.join("missing")).is_err());
    }

    #[test]
    fn nothing_without_downloads_or_when_cancelled() {
        let env = Env::new();
        let runner = FakeRunner::new();
        assert!(DuplicatesScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
        write(&env, "Downloads/a.bin", &blob(3), 2);
        write(&env, "Downloads/b.bin", &blob(3), 1);
        env.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(DuplicatesScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
        assert_eq!(DuplicatesScanner.id(), "duplicates");
        assert!(DuplicatesScanner.supports(Os::MacOs) && !DuplicatesScanner.name().is_empty());
    }
}
