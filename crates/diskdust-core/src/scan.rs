//! Scan orchestration: runs scanners in parallel, streams progress and merges results.

use rayon::prelude::*;

use crate::model::Finding;
use crate::scanners::{ScanContext, Scanner};

/// Progress events emitted during a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanEvent {
    Started { scanner: &'static str, name: &'static str },
    Finished { scanner: &'static str, name: &'static str, found: usize, error: Option<String> },
}

/// Runs every scanner that supports `ctx.os`, calling `emit` as each starts and finishes.
/// Returns the merged, de-duplicated findings sorted by size (largest first).
pub fn run_scan(
    ctx: &ScanContext<'_>,
    scanners: &[Box<dyn Scanner>],
    emit: &(dyn Fn(ScanEvent) + Sync),
) -> Vec<Finding> {
    let found: Vec<Finding> = scanners
        .par_iter()
        .filter(|s| s.supports(ctx.os))
        .flat_map(|scanner| {
            let (id, name) = (scanner.id(), scanner.name());
            emit(ScanEvent::Started { scanner: id, name });
            let span = tracing::info_span!("scan", scanner = id);
            let _guard = span.enter();
            match scanner.scan(ctx) {
                Ok(found) => {
                    emit(ScanEvent::Finished { scanner: id, name, found: found.len(), error: None });
                    found
                }
                Err(e) => {
                    tracing::warn!(error = %e, "scanner failed");
                    emit(ScanEvent::Finished { scanner: id, name, found: 0, error: Some(e.to_string()) });
                    Vec::new()
                }
            }
        })
        .collect();
    let mut merged = dedupe_overlaps(found);
    merged.sort_by(|a, b| b.bytes_or_zero().cmp(&a.bytes_or_zero()).then_with(|| a.title.cmp(&b.title)));
    merged
}

/// Removes findings that would double-count the same bytes.
///
/// For two findings whose paths are equal or nested: a generic finding loses to a more
/// specific one; between equally specific findings the ancestor (larger) one is kept.
/// Duplicate ids are also collapsed.
pub fn dedupe_overlaps(findings: Vec<Finding>) -> Vec<Finding> {
    let n = findings.len();
    let mut dropped = vec![false; n];
    for i in 0..n {
        for j in (i + 1)..n {
            if dropped[i] || dropped[j] {
                continue;
            }
            let (a, b) = (&findings[i], &findings[j]);
            if a.id == b.id {
                dropped[j] = true;
                continue;
            }
            let (Some(pa), Some(pb)) = (&a.path, &b.path) else { continue };
            let a_contains_b = pb.starts_with(pa);
            let b_contains_a = pa.starts_with(pb);
            if !a_contains_b && !b_contains_a {
                continue;
            }
            let loser = if a.specificity != b.specificity {
                if a.specificity > b.specificity { i } else { j }
            } else if a_contains_b {
                j
            } else {
                i
            };
            dropped[loser] = true;
        }
    }
    findings.into_iter().zip(dropped).filter_map(|(f, d)| (!d).then_some(f)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::model::{Category, GENERIC, LOWEST, Os, Privilege, Risk, SPECIFIC};
    use crate::scanners::testutil::{BIG, Env};
    use crate::scanners::{ScanError, default_scanners};
    use std::path::PathBuf;
    use std::sync::Mutex;

    fn finding(id: &str, path: &str, specificity: u8, bytes: u64) -> Finding {
        Finding {
            id: id.into(),
            scanner: "t".into(),
            category: Category::AppCaches,
            title: id.into(),
            detail: String::new(),
            path: Some(PathBuf::from(path)),
            bytes: Some(bytes),
            risk: Risk::Safe,
            privilege: Privilege::User,
            action: None,
            specificity,
            last_modified: None,
            quit_first: None,
        }
    }

    fn ids(v: &[Finding]) -> Vec<&str> {
        v.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn specific_beats_generic_on_equal_path() {
        let out = dedupe_overlaps(vec![
            finding("generic", "/h/.cache/pip", GENERIC, 1),
            finding("specific", "/h/.cache/pip", SPECIFIC, 1),
        ]);
        assert_eq!(ids(&out), ["specific"]);
    }

    #[test]
    fn large_files_never_double_count_other_findings() {
        let out = dedupe_overlaps(vec![
            finding("large", "/h/Library/Caches/app/blob.bin", LOWEST, 5),
            finding("cache", "/h/Library/Caches/app", GENERIC, 6),
            finding("movie", "/h/Movies/a.mov", LOWEST, 7),
        ]);
        assert_eq!(ids(&out), ["cache", "movie"]);
    }

    #[test]
    fn specific_descendant_beats_generic_ancestor() {
        let out = dedupe_overlaps(vec![
            finding("specific", "/h/.cache/huggingface/hub", SPECIFIC, 1),
            finding("generic", "/h/.cache/huggingface", GENERIC, 2),
        ]);
        assert_eq!(ids(&out), ["specific"]);
    }

    #[test]
    fn equal_specificity_keeps_ancestor() {
        let out = dedupe_overlaps(vec![
            finding("child", "/h/a/b", SPECIFIC, 1),
            finding("parent", "/h/a", SPECIFIC, 2),
            finding("other", "/h/ab", SPECIFIC, 3),
        ]);
        assert_eq!(ids(&out), ["parent", "other"]);
        let out =
            dedupe_overlaps(vec![finding("parent", "/h/a", SPECIFIC, 2), finding("child", "/h/a/b", SPECIFIC, 1)]);
        assert_eq!(ids(&out), ["parent"]);
    }

    #[test]
    fn identical_paths_keep_first_and_duplicate_ids_collapse() {
        let out = dedupe_overlaps(vec![finding("a", "/x", SPECIFIC, 1), finding("b", "/x", SPECIFIC, 1)]);
        assert_eq!(ids(&out), ["a"]);
        let mut no_path = finding("same", "/y", SPECIFIC, 1);
        no_path.path = None;
        let out = dedupe_overlaps(vec![no_path.clone(), no_path, finding("z", "/z", SPECIFIC, 1)]);
        assert_eq!(ids(&out), ["same", "z"]);
    }

    #[test]
    fn full_scan_merges_sorts_and_reports_progress() {
        let env = Env::new();
        env.file(".cache/pip/http/a", BIG);
        env.file(".cache/big-app/blob", BIG * 2);
        env.file(".cargo/registry/x", BIG / 2 + 512 * 1024);
        let runner = FakeRunner::new().respond("docker system df --format {{json .}}", false, "");
        let ctx = env.ctx(Os::Linux, &runner);
        let events = Mutex::new(Vec::new());
        let found = run_scan(&ctx, &default_scanners(), &|e| events.lock().expect("lock").push(e));
        let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["big-app", "pip cache", "Cargo registry"]);
        let events = events.into_inner().expect("lock");
        let started = events.iter().filter(|e| matches!(e, ScanEvent::Started { .. })).count();
        let finished = events.iter().filter(|e| matches!(e, ScanEvent::Finished { .. })).count();
        assert_eq!(started, finished);
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Finished { scanner: "docker", error: Some(_), .. })));
        assert!(!events.iter().any(|e| matches!(e, ScanEvent::Started { scanner: "timemachine", .. })));
    }

    #[test]
    fn scan_error_variants_display() {
        let e = ScanError::Unavailable("down".into());
        assert_eq!(e.to_string(), "down");
    }
}
