//! Background scan and clean jobs. The UI thread never blocks on disk or process I/O.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use diskdust_core::clean::DeleteMode;
use diskdust_core::command::SystemRunner;
use diskdust_core::model::{Finding, Os};
use diskdust_core::scan::{ScanEvent, run_scan};
use diskdust_core::scanners::{ScanContext, Scanner, TrashScanner, default_app_dirs, default_scanners};

pub use crate::session::CleanResult;
use crate::session::{Elevation, clean_findings, default_audit_log};

/// Messages from workers to the UI.
#[derive(Debug)]
pub enum Msg {
    Scan(ScanEvent),
    ScanDone {
        findings: Vec<Finding>,
        elapsed: Duration,
        cancelled: bool,
    },
    Cleaned(CleanResult),
    CleanDone,
    /// Largest children of a finding's folder, for the details panel.
    Breakdown {
        id: String,
        entries: Vec<(PathBuf, u64)>,
    },
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

/// Number of sub-folders listed in the details panel.
const BREAKDOWN_LIMIT: usize = 12;

pub fn spawn_breakdown(id: String, path: PathBuf, notifier: Notifier) {
    let spawned = thread::Builder::new().name("diskdust-breakdown".into()).spawn(move || {
        let entries = diskdust_core::size::largest_children(&path, &AtomicBool::new(false), BREAKDOWN_LIMIT);
        notifier.send(Msg::Breakdown { id, entries });
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "failed to start breakdown thread");
    }
}

/// Empties the user's Trash (everything in it, permanently), reporting like a clean.
pub fn spawn_empty_trash(os: Os, home: PathBuf, notifier: Notifier) {
    let spawned = thread::Builder::new().name("diskdust-empty-trash".into()).spawn(move || {
        let runner = SystemRunner::new(&home);
        let cancel = AtomicBool::new(false);
        let ctx = ScanContext {
            os,
            home: home.clone(),
            system_root: PathBuf::from("/"),
            project_roots: Vec::new(),
            app_dirs: Vec::new(),
            runner: &runner,
            cancel: &cancel,
        };
        let scanners: [Box<dyn Scanner>; 1] = [Box::new(TrashScanner)];
        let findings = run_scan(&ctx, &scanners, &|_| {});
        let audit = default_audit_log(os, &home);
        clean_findings(os, &home, &findings, DeleteMode::Permanent, &audit, Elevation::Prompt, &mut |result| {
            notifier.send(Msg::Cleaned(result));
        });
        notifier.send(Msg::CleanDone);
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "failed to start empty-trash thread");
    }
}

pub fn spawn_clean(os: Os, home: PathBuf, findings: Vec<Finding>, mode: DeleteMode, notifier: Notifier) {
    let spawned = thread::Builder::new().name("diskdust-clean".into()).spawn(move || {
        let audit = default_audit_log(os, &home);
        clean_findings(os, &home, &findings, mode, &audit, Elevation::Prompt, &mut |result| {
            notifier.send(Msg::Cleaned(result));
        });
        notifier.send(Msg::CleanDone);
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "failed to start clean thread");
    }
}
