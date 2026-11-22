//! Terminal mode: `diskdust scan` (read-only report) and `diskdust clean` (non-interactive
//! cleanup with the same safety rules as the app; admin items are skipped).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{Context as _, bail};
use diskdust_core::clean::DeleteMode;
use diskdust_core::command::SystemRunner;
use diskdust_core::model::{Category, Finding, Os, Privilege, Risk};
use diskdust_core::scan::{ScanEvent, run_scan};
use diskdust_core::scanners::{ScanContext, default_app_dirs, default_project_roots, default_scanners, unique_dirs};

use crate::format;
use crate::session::{CleanResult, Elevation, clean_findings, default_audit_log};
use crate::settings::{Settings, SettingsStore};

pub const USAGE: &str = "usage:
  diskdust                       open the desktop app
  diskdust scan  [filters] [--json]
                                 print a read-only report
  diskdust clean [filters] (--dry-run | --yes) [--permanent] [--json]
                                 clean matching items (moved to the Trash unless --permanent);
                                 admin items are skipped, ignored items are never touched

filters:
  --category <name>     repeatable: containers, developer-caches, old-toolchains, build-artifacts,
                        installers, app-caches, logs, xcode, device-backups, orphaned-app-data,
                        trash, system
  --safe-only           only items marked Safe
  --older-than <days>   only items untouched for at least this many days (e.g. 30 or 30d)";

/// How `clean` was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// `--dry-run`: list what would be cleaned.
    DryRun,
    /// `--yes`: clean.
    Yes,
}

/// Parsed command-line options shared by `scan` and `clean`.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub json: bool,
    pub categories: Vec<Category>,
    pub safe_only: bool,
    pub older_than: Option<u64>,
    pub confirm: Option<Confirm>,
    pub mode: DeleteMode,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            json: false,
            categories: Vec::new(),
            safe_only: false,
            older_than: None,
            confirm: None,
            mode: DeleteMode::Trash,
        }
    }
}

fn set_confirm(opts: &mut Options, confirm: Confirm) -> anyhow::Result<()> {
    if opts.confirm.is_some_and(|c| c != confirm) {
        bail!("use either --dry-run or --yes, not both");
    }
    opts.confirm = Some(confirm);
    Ok(())
}

pub fn parse(args: &[String]) -> anyhow::Result<Options> {
    let mut opts = Options::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => opts.json = true,
            "--safe-only" => opts.safe_only = true,
            "--dry-run" => set_confirm(&mut opts, Confirm::DryRun)?,
            "--yes" | "-y" => set_confirm(&mut opts, Confirm::Yes)?,
            "--permanent" => opts.mode = DeleteMode::Permanent,
            "--category" => {
                let value = it.next().context("--category needs a value")?;
                let category = Category::from_slug(value).with_context(|| format!("unknown category `{value}`"))?;
                opts.categories.push(category);
            }
            "--older-than" => {
                let value = it.next().context("--older-than needs a number of days")?;
                let days = value
                    .strip_suffix('d')
                    .unwrap_or(value)
                    .parse()
                    .with_context(|| format!("invalid number of days `{value}`"))?;
                opts.older_than = Some(days);
            }
            other => bail!("unknown option `{other}`"),
        }
    }
    Ok(opts)
}

impl Options {
    /// Whether `f` passes the category, risk and age filters.
    pub fn matches(&self, f: &Finding, now: i64) -> bool {
        (self.categories.is_empty() || self.categories.contains(&f.category))
            && (!self.safe_only || (f.is_actionable() && f.risk == Risk::Safe))
            && self.older_than.is_none_or(|days| f.age_days(now).is_some_and(|age| age >= days))
    }
}

fn scan_machine(settings: &Settings) -> anyhow::Result<(Os, PathBuf, Vec<Finding>)> {
    let os = Os::current().context("diskdust supports macOS and Linux only")?;
    let home = dirs::home_dir().context("cannot determine your home directory")?;
    let runner = SystemRunner::new(&home);
    let cancel = AtomicBool::new(false);
    let ctx = ScanContext {
        os,
        home: home.clone(),
        system_root: PathBuf::from("/"),
        project_roots: settings.project_roots.clone().map_or_else(|| default_project_roots(&home), unique_dirs),
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
    let findings = findings.into_iter().filter(|f| !settings.ignored.contains(&f.id)).collect();
    Ok((os, home, findings))
}

pub fn scan(args: &[String]) -> anyhow::Result<()> {
    let opts = parse(args)?;
    let settings = SettingsStore::default_location().load();
    let (_, home, findings) = scan_machine(&settings)?;
    let now = format::now_unix();
    let findings: Vec<Finding> = findings.into_iter().filter(|f| opts.matches(f, now)).collect();
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print!("{}", render_table(&findings, &home));
    }
    Ok(())
}

pub fn clean(args: &[String]) -> anyhow::Result<()> {
    let opts = parse(args)?;
    let Some(confirm) = opts.confirm else {
        bail!("pass --dry-run to preview or --yes to clean\n\n{USAGE}");
    };
    let settings = SettingsStore::default_location().load();
    let (os, home, findings) = scan_machine(&settings)?;
    let now = format::now_unix();
    let chosen: Vec<Finding> = findings.into_iter().filter(|f| f.is_actionable() && opts.matches(f, now)).collect();
    if confirm == Confirm::DryRun {
        if opts.json {
            println!("{}", serde_json::to_string_pretty(&chosen)?);
        } else {
            print!("{}", render_table(&chosen, &home));
            println!("dry run: nothing was removed");
        }
        return Ok(());
    }
    let audit = default_audit_log(os, &home);
    let mut results = Vec::new();
    clean_findings(os, &home, &chosen, opts.mode, &audit, Elevation::Skip, &mut |r| {
        if !opts.json {
            println!("{} {} — {}", if r.ok { "ok  " } else { "FAIL" }, r.title, r.message);
        }
        results.push(r);
    });
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("\n{}", summary(&results));
    }
    let failed = results.iter().filter(|r| !r.ok).count();
    if failed > 0 {
        bail!("{} not cleaned (see above; log: {})", format::items(failed), audit.path().display());
    }
    Ok(())
}

fn summary(results: &[CleanResult]) -> String {
    let ok: Vec<&CleanResult> = results.iter().filter(|r| r.ok).collect();
    let freed: u64 = ok.iter().filter(|r| !r.trashed).filter_map(|r| r.bytes).sum();
    let trashed: u64 = ok.iter().filter(|r| r.trashed).filter_map(|r| r.bytes).sum();
    let mut out = format!("cleaned {}, freed {}", format::items(ok.len()), format::bytes(freed));
    if trashed > 0 {
        let _ = write!(out, ", {} moved to the Trash (empty it to reclaim)", format::bytes(trashed));
    }
    let failed = results.len() - ok.len();
    if failed > 0 {
        let _ = write!(out, ", {failed} not cleaned");
    }
    out
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

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_options() {
        let o = parse(&args(&[
            "--json",
            "--category",
            "build-artifacts",
            "--category",
            "old-toolchains",
            "--safe-only",
            "--older-than",
            "30d",
            "--yes",
            "--permanent",
        ]))
        .expect("parse");
        assert_eq!(
            o,
            Options {
                json: true,
                categories: vec![Category::BuildArtifacts, Category::Toolchains],
                safe_only: true,
                older_than: Some(30),
                confirm: Some(Confirm::Yes),
                mode: DeleteMode::Permanent,
            }
        );
        assert_eq!(parse(&args(&["--dry-run", "--dry-run"])).expect("parse").confirm, Some(Confirm::DryRun));
        assert!(parse(&args(&["--dry-run", "--yes"])).is_err(), "contradictory confirmation");
        assert_eq!(parse(&args(&["--older-than", "7"])).expect("parse").older_than, Some(7));
        for bad in [&["--bogus"][..], &["--category"], &["--category", "nope"], &["--older-than", "x"]] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn filters_by_category_risk_and_age() {
        let now = 10_000_000;
        let mut f = finding("x", Some(5), true, Privilege::User);
        f.last_modified = Some(now - 40 * 86_400);
        let all = Options::default();
        assert!(all.matches(&f, now));
        let other = Options { categories: vec![Category::Logs], ..Options::default() };
        assert!(!other.matches(&f, now));
        let old = Options { older_than: Some(30), ..Options::default() };
        assert!(old.matches(&f, now));
        assert!(!Options { older_than: Some(60), ..Options::default() }.matches(&f, now));
        f.risk = Risk::Review;
        assert!(!Options { safe_only: true, ..Options::default() }.matches(&f, now));
        f.last_modified = None;
        assert!(!old.matches(&f, now), "undated items never pass an age filter");
    }

    #[test]
    fn summary_reports_freed_trashed_and_failed() {
        let r = |ok, bytes, trashed| CleanResult {
            id: "i".into(),
            title: "t".into(),
            ok,
            message: String::new(),
            bytes: Some(bytes),
            trashed,
        };
        assert_eq!(
            summary(&[r(true, 2_000_000, false), r(true, 3_000_000, true), r(false, 1, false)]),
            "cleaned 2 items, freed 2.0 MB, 3.0 MB moved to the Trash (empty it to reclaim), 1 not cleaned"
        );
        assert!(USAGE.contains("--dry-run"));
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
