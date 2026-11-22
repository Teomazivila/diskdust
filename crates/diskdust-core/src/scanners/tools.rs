//! Scanners that ask an installed tool where its data lives.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, is_real_dir, with_shared_note};
use crate::model::{Category, CleanupAction, Finding, KnownCommand, Os, Privilege, Risk, SPECIFIC};
use crate::units::{format_bytes, parse_journal_usage};

/// Age passed to `journalctl --vacuum-time` (keep in sync with [`KnownCommand::JournalVacuum`]).
const JOURNAL_KEEP: Duration = Duration::from_hours(7 * 24);

const TIMEOUT: Duration = Duration::from_secs(30);

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

/// Runs a command and returns stdout when it succeeded; `None` when the tool is missing or failed.
fn query(ctx: &ScanContext<'_>, parts: &[&str]) -> Result<Option<String>, ScanError> {
    if !ctx.runner.exists(parts[0]) {
        return Ok(None);
    }
    let out = ctx.runner.run(&argv(parts), TIMEOUT)?;
    Ok(out.success.then_some(out.stdout))
}

fn measured_finding(
    ctx: &ScanContext<'_>,
    scanner: &str,
    id: &str,
    title: &str,
    path: PathBuf,
    cmd: KnownCommand,
    detail: &str,
) -> Option<Finding> {
    if !is_real_dir(&path) {
        return None;
    }
    let report = ctx.measure(&path)?;
    (report.bytes >= MIN_BYTES).then(|| Finding {
        detail: with_shared_note(detail.to_owned(), &report),
        path: Some(path),
        bytes: Some(report.bytes),
        risk: Risk::Safe,
        action: Some(CleanupAction::Run(cmd)),
        specificity: SPECIFIC,
        ..base_finding(scanner, id.to_owned(), Category::DeveloperCaches, title.to_owned())
    })
}

/// Homebrew download cache (`brew --cache`), cleaned with `brew cleanup --prune=all`.
#[derive(Debug)]
pub struct HomebrewScanner;

impl Scanner for HomebrewScanner {
    fn id(&self) -> &'static str {
        "homebrew"
    }
    fn name(&self) -> &'static str {
        "Homebrew"
    }
    fn supports(&self, _os: Os) -> bool {
        true
    }
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Some(out) = query(ctx, &["brew", "--cache"])? else {
            return Ok(Vec::new());
        };
        let path = PathBuf::from(out.trim());
        Ok(measured_finding(
            ctx,
            "homebrew",
            "homebrew:cache",
            "Homebrew cache",
            path,
            KnownCommand::BrewCleanup,
            "Downloaded bottles and old versions. Cleaned with `brew cleanup --prune=all`.",
        )
        .into_iter()
        .collect())
    }
}

/// Go module and build caches, cleaned with `go clean` (module files are read-only on disk).
#[derive(Debug)]
pub struct GoScanner;

impl Scanner for GoScanner {
    fn id(&self) -> &'static str {
        "go"
    }
    fn name(&self) -> &'static str {
        "Go"
    }
    fn supports(&self, _os: Os) -> bool {
        true
    }
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Some(out) = query(ctx, &["go", "env", "GOMODCACHE", "GOCACHE"])? else {
            return Ok(Vec::new());
        };
        let mut lines = out.lines().map(str::trim);
        let (modcache, buildcache) = (lines.next().unwrap_or_default(), lines.next().unwrap_or_default());
        let mut found = Vec::new();
        if !modcache.is_empty() {
            found.extend(measured_finding(
                ctx,
                "go",
                "go:modcache",
                "Go module cache",
                PathBuf::from(modcache),
                KnownCommand::GoCleanModCache,
                "Downloaded Go modules. Cleaned with `go clean -modcache`; re-downloaded on next build.",
            ));
        }
        if !buildcache.is_empty() {
            found.extend(measured_finding(
                ctx,
                "go",
                "go:buildcache",
                "Go build cache",
                PathBuf::from(buildcache),
                KnownCommand::GoCleanBuildCache,
                "Compiled package cache. Cleaned with `go clean -cache`.",
            ));
        }
        Ok(found)
    }
}

/// Simulators whose runtime is no longer installed (`xcrun simctl delete unavailable`).
#[derive(Debug)]
pub struct SimulatorScanner;

/// Extracts simulator UDIDs (8-4-4-4-12 hex) from `simctl list` text output.
fn parse_udids(text: &str) -> Vec<String> {
    text.split(['(', ')'])
        .filter(|tok| {
            let parts: Vec<_> = tok.split('-').collect();
            parts.len() == 5
                && parts.iter().map(|p| p.len()).eq([8, 4, 4, 4, 12])
                && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        .map(str::to_owned)
        .collect()
}

impl Scanner for SimulatorScanner {
    fn id(&self) -> &'static str {
        "simulators"
    }
    fn name(&self) -> &'static str {
        "Xcode simulators"
    }
    fn supports(&self, os: Os) -> bool {
        os == Os::MacOs
    }
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Some(out) = query(ctx, &["xcrun", "simctl", "list", "devices", "unavailable"])? else {
            return Ok(Vec::new());
        };
        let udids = parse_udids(&out);
        if udids.is_empty() {
            return Ok(Vec::new());
        }
        let devices = ctx.home.join("Library/Developer/CoreSimulator/Devices");
        let Some(bytes) = udids.iter().map(|id| ctx.measure(&devices.join(id)).map(|r| r.bytes)).sum::<Option<u64>>()
        else {
            return Ok(Vec::new());
        };
        Ok(vec![Finding {
            detail: format!("{} simulators whose iOS runtime is no longer installed.", udids.len()),
            path: Some(devices),
            bytes: Some(bytes),
            risk: Risk::Safe,
            action: Some(CleanupAction::Run(KnownCommand::SimctlDeleteUnavailable)),
            specificity: SPECIFIC,
            ..base_finding(
                "simulators",
                "simulators:unavailable".to_owned(),
                Category::Xcode,
                "Unavailable simulators".to_owned(),
            )
        }])
    }
}

/// Time Machine local snapshots (macOS, admin).
#[derive(Debug)]
pub struct TimeMachineScanner;

impl Scanner for TimeMachineScanner {
    fn id(&self) -> &'static str {
        "timemachine"
    }
    fn name(&self) -> &'static str {
        "Time Machine snapshots"
    }
    fn supports(&self, os: Os) -> bool {
        os == Os::MacOs
    }
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Some(out) = query(ctx, &["tmutil", "listlocalsnapshots", "/"])? else {
            return Ok(Vec::new());
        };
        let count = out.lines().filter(|l| l.trim_start().starts_with("com.apple.TimeMachine.")).count();
        if count == 0 {
            return Ok(Vec::new());
        }
        Ok(vec![Finding {
            detail: format!(
                "{count} local snapshots. macOS reports their size as purgeable; deleting them removes local restore points \
                 (backups on your Time Machine disk are unaffected)."
            ),
            privilege: Privilege::Admin,
            action: Some(CleanupAction::Run(KnownCommand::TimeMachineDeleteLocalSnapshots)),
            specificity: SPECIFIC,
            ..base_finding(
                "timemachine",
                "timemachine:local".to_owned(),
                Category::System,
                "Time Machine local snapshots".to_owned(),
            )
        }])
    }
}

/// systemd journal (Linux, admin).
#[derive(Debug)]
pub struct JournalScanner;

impl Scanner for JournalScanner {
    fn id(&self) -> &'static str {
        "journald"
    }
    fn name(&self) -> &'static str {
        "systemd journal"
    }
    fn supports(&self, os: Os) -> bool {
        os == Os::Linux
    }
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Some(out) = query(ctx, &["journalctl", "--disk-usage"])? else {
            return Ok(Vec::new());
        };
        let Some(total) = parse_journal_usage(&out).filter(|b| *b >= MIN_BYTES) else {
            return Ok(Vec::new());
        };
        let cutoff = SystemTime::now().checked_sub(JOURNAL_KEEP).unwrap_or(SystemTime::UNIX_EPOCH);
        let estimate = vacuumable_journal_bytes(&ctx.system_path("/var/log/journal"), cutoff);
        if estimate.is_some_and(|b| b < MIN_BYTES) {
            return Ok(Vec::new());
        }
        let size_note = match estimate {
            Some(_) => {
                format!("Estimate: archived journal files older than 7 days, of {} in total.", format_bytes(total))
            }
            None => format!(
                "The journal uses {} in total; how much is older than 7 days cannot be read without administrator access.",
                format_bytes(total)
            ),
        };
        Ok(vec![Finding {
            detail: format!("System logs. Vacuumed to the last 7 days with `journalctl --vacuum-time=7d`. {size_note}"),
            bytes: estimate,
            risk: Risk::Safe,
            privilege: Privilege::Admin,
            action: Some(CleanupAction::Run(KnownCommand::JournalVacuum)),
            specificity: SPECIFIC,
            ..base_finding("journald", "journald:usage".to_owned(), Category::Logs, "systemd journal".to_owned())
        }])
    }
}

/// Allocated bytes of archived journal files (`name@….journal` / `….journal~`) last written before
/// `cutoff` — what `journalctl --vacuum-time` removes. `None` when the journal is unreadable.
fn vacuumable_journal_bytes(journal_dir: &Path, cutoff: SystemTime) -> Option<u64> {
    let machines = match std::fs::read_dir(journal_dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(0),
        Err(_) => return None,
    };
    let mut total = 0u64;
    for machine in machines.filter_map(Result::ok) {
        if !machine.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        for file in std::fs::read_dir(machine.path()).ok()?.filter_map(Result::ok) {
            let name = file.file_name().to_string_lossy().into_owned();
            let archived = (name.contains('@') && name.ends_with(".journal")) || name.ends_with(".journal~");
            let Ok(meta) = file.metadata() else { continue };
            if archived && meta.is_file() && meta.modified().is_ok_and(|m| m < cutoff) {
                total = total.saturating_add(crate::size::allocated_bytes(&meta));
            }
        }
    }
    Some(total)
}

/// Disabled (superseded) snap revisions (Linux, admin).
#[derive(Debug)]
pub struct SnapScanner;

/// Parses `snap list --all`, returning `(name, revision)` for disabled revisions.
fn parse_disabled_snaps(text: &str) -> Vec<(String, String)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<_> = line.split_whitespace().collect();
            let notes = cols.last()?;
            (cols.len() >= 6 && notes.split(',').any(|n| n == "disabled"))
                .then(|| (cols[0].to_owned(), cols[2].to_owned()))
        })
        .collect()
}

impl Scanner for SnapScanner {
    fn id(&self) -> &'static str {
        "snap"
    }
    fn name(&self) -> &'static str {
        "Snap revisions"
    }
    fn supports(&self, os: Os) -> bool {
        os == Os::Linux
    }
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let Some(out) = query(ctx, &["snap", "list", "--all"])? else {
            return Ok(Vec::new());
        };
        Ok(parse_disabled_snaps(&out)
            .into_iter()
            .filter_map(|(name, revision)| {
                let cmd = KnownCommand::SnapRemoveRevision { name: name.clone(), revision: revision.clone() };
                if !cmd.is_well_formed() {
                    return None;
                }
                let file = ctx.system_path(&format!("/var/lib/snapd/snaps/{name}_{revision}.snap"));
                let bytes = std::fs::symlink_metadata(&file).ok().map(|m| crate::size::allocated_bytes(&m));
                Some(Finding {
                    detail: format!("Old revision {revision} of {name}, kept after an update. Removed with `snap remove --revision`."),
                    path: Some(file),
                    bytes,
                    risk: Risk::Safe,
                    privilege: Privilege::Admin,
                    action: Some(CleanupAction::Run(cmd)),
                    specificity: SPECIFIC,
                    ..base_finding("snap", format!("snap:{name}:{revision}"), Category::System, format!("{name} (revision {revision})"))
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn homebrew_cache_measured() {
        let env = Env::new();
        let cache = env.home.join("Library/Caches/Homebrew");
        env.file("Library/Caches/Homebrew/downloads/x.tar.gz", BIG);
        let runner = FakeRunner::new().respond("brew --cache", true, &format!("{}\n", cache.display()));
        let found = HomebrewScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path.as_deref(), Some(cache.as_path()));
        assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::BrewCleanup)));
    }

    #[test]
    fn homebrew_missing_or_failing() {
        let env = Env::new();
        let none = FakeRunner::new();
        assert!(HomebrewScanner.scan(&env.ctx(Os::MacOs, &none)).expect("scan").is_empty());
        let failing = FakeRunner::new().respond("brew --cache", false, "");
        assert!(HomebrewScanner.scan(&env.ctx(Os::MacOs, &failing)).expect("scan").is_empty());
    }

    #[test]
    fn go_caches_measured() {
        let env = Env::new();
        let modc = env.home.join("go/pkg/mod");
        let build = env.home.join("Library/Caches/go-build");
        env.file("go/pkg/mod/cache/x", BIG);
        env.file("Library/Caches/go-build/00/y", BIG);
        let out = format!("{}\n{}\n", modc.display(), build.display());
        let runner = FakeRunner::new().respond("go env GOMODCACHE GOCACHE", true, &out);
        let found = GoScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        let actions: Vec<_> = found.iter().map(|f| f.action.clone()).collect();
        assert_eq!(
            actions,
            [
                Some(CleanupAction::Run(KnownCommand::GoCleanModCache)),
                Some(CleanupAction::Run(KnownCommand::GoCleanBuildCache))
            ]
        );
    }

    #[test]
    fn go_handles_empty_env() {
        let env = Env::new();
        let runner = FakeRunner::new().respond("go env GOMODCACHE GOCACHE", true, "\n\n");
        assert!(GoScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
    }

    #[test]
    fn udid_parsing() {
        let text = "== Devices ==\n-- iOS 15.0 --\n    iPhone 13 (5A1C2B3D-1111-2222-3333-444455556666) (Shutdown) (unavailable, runtime profile not found)\n    Bad (1234)\n";
        assert_eq!(parse_udids(text), ["5A1C2B3D-1111-2222-3333-444455556666"]);
        assert!(parse_udids("(GGGGGGGG-1111-2222-3333-444455556666)").is_empty());
    }

    #[test]
    fn simulators_found_and_sized() {
        let env = Env::new();
        let id = "5A1C2B3D-1111-2222-3333-444455556666";
        env.file(&format!("Library/Developer/CoreSimulator/Devices/{id}/data/img"), BIG);
        let runner = FakeRunner::new().respond(
            "xcrun simctl list devices unavailable",
            true,
            &format!("-- iOS 15.0 --\n    iPhone ({id}) (Shutdown) (unavailable)\n"),
        );
        let found = SimulatorScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(found.len(), 1);
        assert!(found[0].bytes.expect("bytes") >= BIG as u64);
        let empty = FakeRunner::new().respond("xcrun simctl list devices unavailable", true, "== Devices ==\n");
        assert!(SimulatorScanner.scan(&env.ctx(Os::MacOs, &empty)).expect("scan").is_empty());
        assert!(!SimulatorScanner.supports(Os::Linux));
    }

    #[test]
    fn time_machine_snapshots_counted() {
        let env = Env::new();
        let runner = FakeRunner::new().respond(
            "tmutil listlocalsnapshots /",
            true,
            "Snapshots for disk /:\ncom.apple.TimeMachine.2026-11-20-101010.local\ncom.apple.TimeMachine.2026-11-21-101010.local\n",
        );
        let found = TimeMachineScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].privilege, Privilege::Admin);
        assert_eq!(found[0].bytes, None);
        assert!(found[0].detail.starts_with("2 local snapshots"));
        let none = FakeRunner::new().respond("tmutil listlocalsnapshots /", true, "Snapshots for disk /:\n");
        assert!(TimeMachineScanner.scan(&env.ctx(Os::MacOs, &none)).expect("scan").is_empty());
    }

    fn age(path: &Path, days: u64) {
        let file = std::fs::File::options().write(true).open(path).expect("open");
        file.set_modified(SystemTime::now() - Duration::from_hours(days * 24)).expect("set mtime");
    }

    #[test]
    fn journal_estimate_counts_only_old_archived_files() {
        let env = Env::new();
        let dir = "var/log/journal/0123abcd";
        let old = env.sys_file(&format!("{dir}/system@0001-0002-0003.journal"), BIG);
        let corrupt = env.sys_file(&format!("{dir}/user-1000@0004.journal~"), BIG);
        let recent = env.sys_file(&format!("{dir}/user-1000@0005-0006.journal"), BIG);
        let active = env.sys_file(&format!("{dir}/system.journal"), BIG);
        for p in [&old, &corrupt, &active] {
            age(p, 30);
        }
        age(&recent, 2);
        let runner = FakeRunner::new().respond(
            "journalctl --disk-usage",
            true,
            "Archived and active journals take up 1.5G in the file system.\n",
        );
        let found = JournalScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        let bytes = found[0].bytes.expect("estimate");
        assert!(bytes >= 2 * BIG as u64 && bytes < 3 * BIG as u64, "only the two old archived files: {bytes}");
        assert!(found[0].detail.contains("of 1.6 GB in total"), "{}", found[0].detail);
        assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::JournalVacuum)));
    }

    #[test]
    fn journal_without_old_files_or_unreadable() {
        let env = Env::new();
        let runner = FakeRunner::new().respond(
            "journalctl --disk-usage",
            true,
            "Archived and active journals take up 1.5G in the file system.\n",
        );
        // Volatile journal only (no /var/log/journal): nothing older to vacuum.
        assert!(JournalScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
        let dir = env.system.join("var/log/journal");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let found = JournalScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
        // Root ignores permission bits (CI containers); only assert when the read was refused.
        if let Some(f) = found.first() {
            assert_eq!(f.bytes, None);
            assert!(f.detail.contains("cannot be read without administrator access"));
        }
        let small =
            FakeRunner::new().respond("journalctl --disk-usage", true, "Journals take up 8.0K in the file system.");
        assert!(JournalScanner.scan(&env.ctx(Os::Linux, &small)).expect("scan").is_empty());
        assert!(JournalScanner.supports(Os::Linux) && !JournalScanner.supports(Os::MacOs));
    }

    #[test]
    fn snap_disabled_revisions() {
        let env = Env::new();
        env.sys_file("var/lib/snapd/snaps/core22_1033.snap", BIG);
        let listing = "Name    Version   Rev    Tracking       Publisher   Notes\n\
                       core22  20240111  1122   latest/stable  canonical✓  base\n\
                       core22  20231123  1033   latest/stable  canonical✓  base,disabled\n\
                       firefox 120.0     3358   latest/stable  mozilla✓    disabled\n";
        let runner = FakeRunner::new().respond("snap list --all", true, listing);
        let found = SnapScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].title, "core22 (revision 1033)");
        assert!(found[0].bytes.expect("bytes") >= BIG as u64);
        assert_eq!(found[1].bytes, None);
        assert!(matches!(found[1].action, Some(CleanupAction::Run(KnownCommand::SnapRemoveRevision { .. }))));
    }

    #[test]
    fn snap_rejects_malformed_rows() {
        let listing = "Name Version Rev Tracking Publisher Notes\n--evil 1 1 x y disabled\nshort disabled\n";
        assert_eq!(parse_disabled_snaps(listing).len(), 1);
        let env = Env::new();
        let runner = FakeRunner::new().respond("snap list --all", true, listing);
        assert!(SnapScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
    }

    #[test]
    fn scanner_metadata() {
        let all: [&dyn Scanner; 6] =
            [&HomebrewScanner, &GoScanner, &SimulatorScanner, &TimeMachineScanner, &JournalScanner, &SnapScanner];
        for s in all {
            assert!(!s.id().is_empty() && !s.name().is_empty());
        }
        assert!(HomebrewScanner.supports(Os::Linux) && GoScanner.supports(Os::MacOs));
        assert!(TimeMachineScanner.supports(Os::MacOs) && SnapScanner.supports(Os::Linux));
    }
}
