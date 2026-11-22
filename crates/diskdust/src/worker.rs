//! Background scan and clean jobs. The UI thread never blocks on disk or process I/O.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use diskdust_core::audit::{AuditEntry, AuditLog};
use diskdust_core::clean::{Cleaner, DeleteMode, SystemTrash, quit_first_reason};
use diskdust_core::command::{CommandRunner, SystemRunner};
use diskdust_core::model::{CleanupAction, Finding, Os, Privilege};
use diskdust_core::privilege::{
    HelperResult, describe_elevation_failure, elevation_argv, encode_payload, helper_executable, parse_helper_output,
};
use diskdust_core::safety::SafetyPolicy;
use diskdust_core::scan::{ScanEvent, run_scan};
use diskdust_core::scanners::{ScanContext, default_app_dirs, default_scanners};
use diskdust_core::units::parse_docker_reclaimed;

/// Messages from workers to the UI.
#[derive(Debug)]
pub enum Msg {
    Scan(ScanEvent),
    ScanDone { findings: Vec<Finding>, elapsed: Duration, cancelled: bool },
    Cleaned(CleanResult),
    CleanDone,
}

#[derive(Debug, Clone)]
pub struct CleanResult {
    pub id: String,
    pub title: String,
    pub ok: bool,
    pub message: String,
    /// Bytes the item occupied, if known.
    pub bytes: Option<u64>,
    /// True when the item was moved to the Trash (space not yet reclaimed).
    pub trashed: bool,
}

/// Notifies the UI thread; failures mean the window closed, which is fine to ignore.
#[derive(Clone)]
pub struct Notifier {
    tx: Sender<Msg>,
    ctx: egui::Context,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Notifier")
    }
}

impl Notifier {
    pub fn new(tx: Sender<Msg>, ctx: egui::Context) -> Self {
        Self { tx, ctx }
    }

    fn send(&self, msg: Msg) {
        let _ = self.tx.send(msg);
        self.ctx.request_repaint();
    }
}

pub fn spawn_scan(os: Os, home: PathBuf, project_roots: Vec<PathBuf>, cancel: Arc<AtomicBool>, notifier: Notifier) {
    let spawned = thread::Builder::new().name("diskdust-scan".into()).spawn(move || {
        let runner = SystemRunner::new(&home);
        let started = Instant::now();
        let ctx = ScanContext {
            os,
            home: home.clone(),
            system_root: PathBuf::from("/"),
            project_roots,
            app_dirs: default_app_dirs(&home),
            runner: &runner,
            cancel: &cancel,
        };
        let emit = |event| notifier.send(Msg::Scan(event));
        let findings = run_scan(&ctx, &default_scanners(), &emit);
        let cancelled = ctx.is_cancelled();
        notifier.send(Msg::ScanDone { findings, elapsed: started.elapsed(), cancelled });
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "failed to start scan thread");
    }
}

pub fn spawn_clean(os: Os, home: PathBuf, findings: Vec<Finding>, mode: DeleteMode, notifier: Notifier) {
    let spawned = thread::Builder::new().name("diskdust-clean".into()).spawn(move || {
        clean(os, &home, &findings, mode, &notifier);
        notifier.send(Msg::CleanDone);
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "failed to start clean thread");
    }
}

fn clean(os: Os, home: &Path, findings: &[Finding], mode: DeleteMode, notifier: &Notifier) {
    let runner = SystemRunner::new(home);
    let policy = SafetyPolicy::for_home(home);
    let audit = AuditLog::default_location(home, os, std::env::var_os("XDG_STATE_HOME").map(PathBuf::from));
    let cleaner = Cleaner { policy: &policy, runner: &runner, trasher: &SystemTrash, mode, allow_admin: false };
    let run_id = AuditEntry::new_run_id();
    tracing::info!(run_id = %run_id, items = findings.len(), ?mode, "clean started");
    let report = |finding: &Finding, action: &CleanupAction, ok: bool, message: String, elevated: bool| {
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
        notifier.send(Msg::Cleaned(CleanResult {
            id: finding.id.clone(),
            title: finding.title.clone(),
            ok,
            bytes,
            message,
            trashed,
        }));
    };

    let (admin, user): (Vec<&Finding>, Vec<&Finding>) =
        findings.iter().filter(|f| f.action.is_some()).partition(|f| f.privilege == Privilege::Admin);

    for finding in user {
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

    if !admin.is_empty() {
        let actions: Vec<CleanupAction> = admin.iter().filter_map(|f| f.action.clone()).collect();
        let results = run_elevated(os, &runner, &actions);
        for ((finding, action), result) in admin.iter().zip(&actions).zip(results) {
            report(finding, action, result.ok, result.message, true);
        }
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
    use diskdust_core::model::{Category, KnownCommand, Risk, SPECIFIC};

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
}
