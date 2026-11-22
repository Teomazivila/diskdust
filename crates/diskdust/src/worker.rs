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
use diskdust_core::scanners::{ScanContext, default_app_dirs, default_scanners};

pub use crate::session::CleanResult;
use crate::session::{Elevation, clean_findings, default_audit_log};

/// Messages from workers to the UI.
#[derive(Debug)]
pub enum Msg {
    Scan(ScanEvent),
    ScanDone { findings: Vec<Finding>, elapsed: Duration, cancelled: bool },
    Cleaned(CleanResult),
    CleanDone,
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
