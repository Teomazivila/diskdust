//! Read-only terminal report: `diskdust scan [--json]`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::Context as _;
use diskdust_core::command::SystemRunner;
use diskdust_core::model::{Finding, Os, Privilege, Risk};
use diskdust_core::scan::{ScanEvent, run_scan};
use diskdust_core::scanners::{ScanContext, default_app_dirs, default_project_roots, default_scanners};

use crate::format;

pub fn scan(json: bool) -> anyhow::Result<()> {
    let os = Os::current().context("diskdust supports macOS and Linux only")?;
    let home = dirs::home_dir().context("cannot determine your home directory")?;
    let runner = SystemRunner::new(&home);
    let cancel = AtomicBool::new(false);
    let ctx = ScanContext {
        os,
        home: home.clone(),
        system_root: PathBuf::from("/"),
        project_roots: default_project_roots(&home),
        app_dirs: default_app_dirs(&home),
        runner: &runner,
        cancel: &cancel,
    };
    let emit = |event: ScanEvent| {
        if let ScanEvent::Finished { name, error: Some(error), .. } = event {
            eprintln!("warning: {name}: {error}");
        }
    };
    let findings = run_scan(&ctx, &default_scanners(), &emit);
    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print!("{}", render_table(&findings, &home));
    }
    Ok(())
}

fn render_table(findings: &[Finding], home: &Path) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{:>10}  {:<6}  {:<18}  {:<40}  PATH", "SIZE", "RISK", "CATEGORY", "ITEM");
    for f in findings {
        let risk = match (f.is_actionable(), f.risk) {
            (false, _) => "info",
            (true, Risk::Safe) => "safe",
            (true, Risk::Review) => "review",
        };
        let lock = if f.privilege == Privilege::Admin { " [admin]" } else { "" };
        let title: String = format!("{}{lock}", f.title).chars().take(40).collect();
        let path = f.path.as_deref().map_or_else(String::new, |p| {
            p.strip_prefix(home).map_or_else(|_| p.display().to_string(), |r| format!("~/{}", r.display()))
        });
        let _ = writeln!(
            out,
            "{:>10}  {:<6}  {:<18}  {:<40}  {}",
            format::maybe_bytes(f.bytes).replace("size unknown", "?"),
            risk,
            f.category.label(),
            title,
            path
        );
    }
    let total: u64 = findings.iter().filter(|f| f.is_actionable()).map(Finding::bytes_or_zero).sum();
    let _ = writeln!(out, "\n{} items, {} reclaimable", findings.len(), format::bytes(total));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use diskdust_core::model::{Category, CleanupAction, KnownCommand, SPECIFIC};

    fn finding(title: &str, bytes: Option<u64>, action: bool, privilege: Privilege) -> Finding {
        Finding {
            id: title.into(),
            scanner: "t".into(),
            category: Category::DeveloperCaches,
            title: title.into(),
            detail: String::new(),
            path: Some(PathBuf::from("/Users/a/.cargo/registry")),
            bytes,
            risk: Risk::Safe,
            privilege,
            action: action.then_some(CleanupAction::Run(KnownCommand::BrewCleanup)),
            specificity: SPECIFIC,
            last_modified: None,
            quit_first: None,
        }
    }

    #[test]
    fn renders_rows_and_total() {
        let table = render_table(
            &[
                finding("Cargo registry", Some(2_000_000_000), true, Privilege::User),
                finding("Snapshots", None, true, Privilege::Admin),
                finding("Disk image", Some(5_000_000_000), false, Privilege::User),
            ],
            Path::new("/Users/a"),
        );
        assert!(table.contains("2.0 GB  safe    Developer caches    Cargo registry"));
        assert!(table.contains("~/.cargo/registry"));
        assert!(table.contains("Snapshots [admin]"));
        assert!(table.contains("info"));
        assert!(table.ends_with("3 items, 2.0 GB reclaimable\n"));
    }
}
