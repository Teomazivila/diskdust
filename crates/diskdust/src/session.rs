//! One clean run, shared by the desktop app and `diskdust clean`: guards, user-level cleanup,
//! elevation for admin items, and the audit log.

use std::path::{Path, PathBuf};
use std::time::Duration;

use diskdust_core::audit::{AuditEntry, AuditLog};
use diskdust_core::clean::{Cleaner, DeleteMode, SystemTrash, quit_first_reason};
use diskdust_core::command::{CommandRunner, SystemRunner};
use diskdust_core::model::{CleanupAction, Finding, KnownCommand, Os, Privilege};
use diskdust_core::privilege::{
    HelperResult, describe_elevation_failure, elevation_argv, encode_payload, helper_executable, parse_helper_output,
};
use diskdust_core::safety::SafetyPolicy;
use diskdust_core::units::parse_docker_reclaimed;
use serde::Serialize;

/// Outcome of cleaning one item.
#[derive(Debug, Clone, Serialize)]
pub struct CleanResult {
    pub id: String,
    pub title: String,
    pub ok: bool,
    pub message: String,
    /// Bytes the item occupied (or Docker's reclaimed figure), if known.
    pub bytes: Option<u64>,
    /// True when the item was moved to the Trash (space not yet reclaimed).
    pub trashed: bool,
}

/// How admin items are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// Run them through the privileged helper behind the OS password prompt.
    Prompt,
    /// Report them as skipped (non-interactive use).
    Skip,
}

/// Message for admin items skipped by [`Elevation::Skip`].
pub const ADMIN_SKIPPED: &str = "needs administrator access; clean it from the desktop app";

/// Default audit log for this machine.
pub fn default_audit_log(os: Os, home: &Path) -> AuditLog {
    AuditLog::default_location(home, os, std::env::var_os("XDG_STATE_HOME").map(PathBuf::from))
}

/// Whether cleaning `finding` permanently empties the user's Trash.
fn empties_trash(finding: &Finding) -> bool {
    matches!(finding.action, Some(CleanupAction::EmptyDir { .. } | CleanupAction::Run(KnownCommand::FinderEmptyTrash)))
}

/// User-level findings in execution order. Emptying the Trash always runs **first**: otherwise
/// items moved to the Trash earlier in the same run would be erased with it, silently turning a
/// recoverable "Move to Trash" into a permanent delete.
fn user_order<'a>(findings: &[&'a Finding]) -> Vec<&'a Finding> {
    let (mut first, rest): (Vec<&Finding>, Vec<&Finding>) = findings.iter().partition(|f| empties_trash(f));
    first.extend(rest);
    first
}

/// Cleans every actionable finding, calling `on_result` once per item, in order: Trash-emptying
/// items first, then the other user items, then admin items.
pub fn clean_findings(
    os: Os,
    home: &Path,
    findings: &[Finding],
    mode: DeleteMode,
    audit: &AuditLog,
    elevation: Elevation,
    on_result: &mut dyn FnMut(CleanResult),
) {
    let runner = SystemRunner::new(home);
    let policy = SafetyPolicy::for_home(home);
    let cleaner = Cleaner { policy: &policy, runner: &runner, trasher: &SystemTrash, mode, allow_admin: false };
    let run_id = AuditEntry::new_run_id();
    tracing::info!(run_id = %run_id, items = findings.len(), ?mode, "clean started");
    let mut report = |finding: &Finding, action: &CleanupAction, ok: bool, message: String, elevated: bool| {
        let trashed =
            ok && !elevated && mode == DeleteMode::Trash && matches!(action, CleanupAction::RemovePath { .. });
        let bytes = reclaimed_bytes(finding, action, ok, &message);
        let entry = AuditEntry {
            timestamp: AuditEntry::now(),
            run_id: run_id.clone(),
            finding_id: finding.id.clone(),
            title: finding.title.clone(),
            path: finding.path.clone(),
            bytes,
            action: action.clone(),
            mode: if elevated { DeleteMode::Permanent } else { mode },
            elevated,
            ok,
            message: message.clone(),
        };
        if let Err(e) = audit.append(&entry) {
            tracing::warn!(run_id = %run_id, error = %e, path = %audit.path().display(), "could not write audit log");
        }
        on_result(CleanResult { id: finding.id.clone(), title: finding.title.clone(), ok, bytes, message, trashed });
    };

    let (admin, user): (Vec<&Finding>, Vec<&Finding>) =
        findings.iter().filter(|f| f.action.is_some()).partition(|f| f.privilege == Privilege::Admin);

    for finding in user_order(&user) {
        let Some(action) = &finding.action else { continue };
        if let Some(reason) = quit_first_reason(&runner, finding) {
            report(finding, action, false, reason, false);
            continue;
        }
        match cleaner.execute(action) {
            Ok(message) => report(finding, action, true, message, false),
            Err(e) => report(finding, action, false, e.to_string(), false),
        }
    }

    if admin.is_empty() {
        return;
    }
    let actions: Vec<CleanupAction> = admin.iter().filter_map(|f| f.action.clone()).collect();
    let results = match elevation {
        Elevation::Prompt => run_elevated(os, &runner, &actions),
        Elevation::Skip => {
            actions.iter().map(|_| HelperResult { ok: false, message: ADMIN_SKIPPED.to_owned() }).collect()
        }
    };
    for ((finding, action), result) in admin.iter().zip(&actions).zip(results) {
        report(finding, action, result.ok, result.message, elevation == Elevation::Prompt);
    }
}

/// Bytes actually freed: Docker prunes report the real figure (often different from the estimate
/// shown before cleaning); everything else uses the scanned size.
fn reclaimed_bytes(finding: &Finding, action: &CleanupAction, ok: bool, message: &str) -> Option<u64> {
    match action {
        CleanupAction::Run(cmd) if ok && cmd.is_docker_prune() => parse_docker_reclaimed(message).or(finding.bytes),
        _ => finding.bytes,
    }
}

/// Runs admin actions through the privileged helper behind the OS authorization prompt.
fn run_elevated(os: Os, runner: &dyn CommandRunner, actions: &[CleanupAction]) -> Vec<HelperResult> {
    let fail_all =
        |message: String| actions.iter().map(|_| HelperResult { ok: false, message: message.clone() }).collect();
    let exe = match std::env::current_exe() {
        Ok(exe) => helper_executable(exe, std::env::var_os("APPIMAGE").as_deref()),
        Err(e) => return fail_all(format!("cannot locate the diskdust executable: {e}")),
    };
    let payload = match encode_payload(actions) {
        Ok(payload) => payload,
        Err(e) => return fail_all(e.to_string()),
    };
    let argv = elevation_argv(os, &exe, &payload);
    match runner.run(&argv, Duration::from_mins(30)) {
        Ok(out) if out.success => parse_helper_output(&out.stdout, actions.len()),
        Ok(out) => fail_all(describe_elevation_failure(os, out.code, &out.stderr)),
        Err(e) => fail_all(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diskdust_core::model::{Category, Risk, SPECIFIC};

    fn finding(bytes: Option<u64>) -> Finding {
        Finding {
            id: "x".into(),
            scanner: "t".into(),
            category: Category::Containers,
            title: "x".into(),
            detail: String::new(),
            path: None,
            bytes,
            risk: Risk::Safe,
            privilege: Privilege::User,
            action: None,
            specificity: SPECIFIC,
            last_modified: None,
            quit_first: None,
        }
    }

    #[test]
    fn docker_prunes_report_actual_reclaimed_space() {
        let build_cache = CleanupAction::Run(KnownCommand::DockerPruneBuildCache);
        let f = finding(Some(12_850_000_000));
        assert_eq!(reclaimed_bytes(&f, &build_cache, true, "Total:\t26.48GB"), Some(26_480_000_000));
        assert_eq!(reclaimed_bytes(&f, &build_cache, true, "unexpected"), Some(12_850_000_000));
        let brew = CleanupAction::Run(KnownCommand::BrewCleanup);
        assert_eq!(reclaimed_bytes(&f, &brew, true, "Total: 1GB"), Some(12_850_000_000));
    }

    #[test]
    fn cleans_user_items_skips_admin_and_audits_everything() {
        let home = tempfile::tempdir().expect("tempdir");
        let home = home.path().canonicalize().expect("canonical");
        let root = home.join("cache");
        let target = root.join("stale");
        std::fs::create_dir_all(&target).expect("mkdir");
        std::fs::write(target.join("blob"), vec![0u8; 4096]).expect("write");
        let mut user = finding(Some(4096));
        user.id = "stale".into();
        user.action = Some(CleanupAction::RemovePath { path: target.clone(), root });
        let mut admin = finding(None);
        admin.id = "apt".into();
        admin.privilege = Privilege::Admin;
        admin.action = Some(CleanupAction::Run(KnownCommand::AptClean));
        let info = finding(Some(1));
        let audit = AuditLog::new(home.join("audit.jsonl"));
        let mut results = Vec::new();
        clean_findings(
            Os::current().expect("os"),
            &home,
            &[admin, info, user],
            DeleteMode::Permanent,
            &audit,
            Elevation::Skip,
            &mut |r| results.push(r),
        );
        let summary: Vec<_> = results.iter().map(|r| (r.id.as_str(), r.ok)).collect();
        assert_eq!(summary, [("stale", true), ("apt", false)], "user first, admin skipped, info ignored");
        assert_eq!(results[1].message, ADMIN_SKIPPED);
        assert!(!target.exists());
        let log = std::fs::read_to_string(audit.path()).expect("audit");
        assert_eq!(log.lines().count(), 2);
    }

    #[test]
    fn trash_is_emptied_before_anything_is_moved_into_it() {
        let home = tempfile::tempdir().expect("tempdir");
        let home = home.path().canonicalize().expect("canonical");
        let trash = home.join("Trash");
        std::fs::create_dir_all(&trash).expect("mkdir");
        std::fs::write(trash.join("old"), b"x").expect("write");
        let cache = home.join("cache");
        let big = cache.join("big");
        std::fs::create_dir_all(&big).expect("mkdir");
        std::fs::write(big.join("blob"), vec![0u8; 8192]).expect("write");

        // Largest first, as the scan orders them: the cache comes before the Trash.
        let mut cache_item = finding(Some(8192));
        cache_item.id = "big".into();
        cache_item.action = Some(CleanupAction::RemovePath { path: big.clone(), root: cache });
        let mut trash_item = finding(Some(1));
        trash_item.id = "trash:user".into();
        trash_item.category = Category::Trash;
        trash_item.action = Some(CleanupAction::EmptyDir { path: trash.clone(), root: home.clone() });

        let audit = AuditLog::new(home.join("audit.jsonl"));
        let mut order = Vec::new();
        clean_findings(
            Os::current().expect("os"),
            &home,
            &[cache_item, trash_item],
            DeleteMode::Permanent,
            &audit,
            Elevation::Skip,
            &mut |r| order.push((r.id, r.ok)),
        );
        assert_eq!(order, [("trash:user".to_owned(), true), ("big".to_owned(), true)]);
        assert!(trash.is_dir() && std::fs::read_dir(&trash).expect("read").next().is_none());
    }

    #[test]
    fn finder_empty_trash_also_runs_first() {
        let mut other = finding(Some(9));
        other.id = "a".into();
        other.action = Some(CleanupAction::Run(KnownCommand::BrewCleanup));
        let mut finder = finding(None);
        finder.id = "trash".into();
        finder.action = Some(CleanupAction::Run(KnownCommand::FinderEmptyTrash));
        let ordered: Vec<_> = user_order(&[&other, &finder]).iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ordered, ["trash", "a"]);
    }
}
