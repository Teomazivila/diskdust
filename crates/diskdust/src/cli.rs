//! Terminal mode: `diskdust scan` (read-only report) and `diskdust clean` (non-interactive
//! cleanup with the same safety rules as the app; admin items are skipped).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{Context as _, bail};
use diskdust_core::clean::DeleteMode;
use diskdust_core::command::SystemRunner;
use diskdust_core::disk;
use diskdust_core::model::{Category, Finding, Os, Privilege, Risk};
use diskdust_core::scan::{ScanEvent, run_scan};
use diskdust_core::scanners::{ScanContext, default_app_dirs, default_project_roots, scanners_for, unique_dirs};

use crate::format;
use crate::session::{CleanResult, Elevation, clean_findings, default_audit_log};
use crate::settings::{Loaded, Settings, SettingsStore};

pub const USAGE: &str = "usage:
  diskdust                       open the desktop app
  diskdust scan  [filters] [--json]
                                 print a read-only report
  diskdust clean [filters] (--dry-run | --yes) [--include-review] [--permanent] [--json]
                                 clean matching items (moved to the Trash unless --permanent);
                                 Safe items only unless --include-review; the Trash is emptied
                                 only with --category trash; admin items are left to the
                                 desktop app and ignored items are never touched

filters:
  --category <name>     repeatable: containers, developer-caches, old-toolchains, build-artifacts,
                        installers, app-caches, logs, xcode, device-backups, orphaned-app-data,
                        trash, system
  --safe-only           only items marked Safe
  --older-than <days>   only items untouched for at least this many days (e.g. 30 or 30d)
  --large-files         also search your home folder for large files (cleaned only with
                        --category large-files)";

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
// Independent on/off command-line switches; grouping them would not make them less independent.
#[allow(clippy::struct_excessive_bools)]
pub struct Options {
    pub json: bool,
    pub categories: Vec<Category>,
    pub safe_only: bool,
    pub older_than: Option<u64>,
    pub confirm: Option<Confirm>,
    pub mode: DeleteMode,
    /// `clean` also takes items marked Review (they may hold data you want).
    pub include_review: bool,
    /// Also search the home folder for large files (in addition to the saved setting).
    pub large_files: bool,
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
            include_review: false,
            large_files: false,
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
            "--include-review" => opts.include_review = true,
            "--large-files" => opts.large_files = true,
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

/// Why `clean` left a matching item out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldBack {
    /// Marked Review and `--include-review` was not given.
    Review,
    /// Must be asked for by name with `--category`: the Trash (emptying it is permanent) and
    /// large files (personal files).
    NeedsCategory(Category),
    /// Needs the administrator password, which only the desktop app can ask for.
    Admin,
}

/// Categories `clean` only touches when named with `--category`.
const EXPLICIT_CATEGORIES: [Category; 2] = [Category::Trash, Category::LargeFiles];

impl Options {
    /// Extra conditions `clean` applies on top of [`Self::matches`]: Review items need
    /// `--include-review`, and the Trash (always emptied permanently) must be asked for by name.
    pub fn held_back(&self, f: &Finding) -> Option<HeldBack> {
        if f.privilege == Privilege::Admin {
            Some(HeldBack::Admin)
        } else if EXPLICIT_CATEGORIES.contains(&f.category) && !self.categories.contains(&f.category) {
            Some(HeldBack::NeedsCategory(f.category))
        } else if f.risk == Risk::Review && !self.include_review {
            Some(HeldBack::Review)
        } else {
            None
        }
    }

    /// Splits matching actionable findings into those `clean` will take and those it holds back.
    pub fn select_for_clean(&self, findings: Vec<Finding>, now: i64) -> (Vec<Finding>, Vec<(Finding, HeldBack)>) {
        let mut chosen = Vec::new();
        let mut held = Vec::new();
        for f in findings.into_iter().filter(|f| f.is_actionable() && self.matches(f, now)) {
            match self.held_back(&f) {
                None => chosen.push(f),
                Some(reason) => held.push((f, reason)),
            }
        }
        (chosen, held)
    }

    /// Whether `f` passes the category, risk and age filters.
    pub fn matches(&self, f: &Finding, now: i64) -> bool {
        (self.categories.is_empty() || self.categories.contains(&f.category))
            && (!self.safe_only || (f.is_actionable() && f.risk == Risk::Safe))
            && self.older_than.is_none_or(|days| f.age_days(now).is_some_and(|age| age >= days))
    }
}

fn scan_machine(settings: &Settings, large_files: bool) -> anyhow::Result<(Os, PathBuf, Vec<Finding>)> {
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
    let findings = run_scan(&ctx, &scanners_for(large_files || settings.large_files), &emit);
    let findings = findings.into_iter().filter(|f| !settings.ignored.contains(&f.id)).collect();
    Ok((os, home, findings))
}

/// Settings for `clean`, which must honour the ignore list: refuses when the file could not be read.
fn settings_for_clean(loaded: Loaded) -> anyhow::Result<Settings> {
    if let Some(problem) = loaded.problem {
        bail!("{problem}\nrefusing to clean: ignored items might not be respected. Fix or delete the settings file.");
    }
    Ok(loaded.settings)
}

pub fn scan(args: &[String]) -> anyhow::Result<()> {
    let opts = parse(args)?;
    let loaded = SettingsStore::default_location().load();
    if let Some(problem) = &loaded.problem {
        eprintln!("warning: {problem}; using defaults for those settings");
    }
    let settings = loaded.settings;
    let (_, home, findings) = scan_machine(&settings, opts.large_files)?;
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
    let settings = settings_for_clean(SettingsStore::default_location().load())?;
    let (os, home, findings) = scan_machine(&settings, opts.large_files)?;
    let now = format::now_unix();
    let (chosen, held) = opts.select_for_clean(findings, now);
    if !opts.json && !held.is_empty() {
        eprintln!("{}", held_back_note(&held));
    }
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
    let before = disk::space(&home);
    clean_findings(os, &home, &chosen, opts.mode, &audit, Elevation::Skip, &mut |r| {
        if !opts.json {
            println!("{} {} — {}", if r.ok { "ok  " } else { "FAIL" }, r.title, r.message);
        }
        results.push(r);
    });
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("\n{}", summary(&results, disk::gained(before, disk::space(&home))));
    }
    let failed = results.iter().filter(|r| !r.ok).count();
    if failed > 0 {
        bail!("{} not cleaned (see above; log: {})", format::items(failed), audit.path().display());
    }
    Ok(())
}

/// "1 item needs", "3 items need".
fn needs(n: usize) -> String {
    if n == 1 { "1 item needs".to_owned() } else { format!("{n} items need") }
}

/// Explains which matching items `clean` left out and how to include them.
fn held_back_note(held: &[(Finding, HeldBack)]) -> String {
    let review = held.iter().filter(|(_, r)| *r == HeldBack::Review).count();
    let trash = held.iter().any(|(_, r)| *r == HeldBack::NeedsCategory(Category::Trash));
    let large = held.iter().filter(|(_, r)| *r == HeldBack::NeedsCategory(Category::LargeFiles)).count();
    let admin = held.iter().filter(|(_, r)| *r == HeldBack::Admin).count();
    let mut parts = Vec::new();
    if review > 0 {
        parts.push(format!("{} marked Review (add --include-review)", format::items_are(review)));
    }
    if trash {
        parts.push("the Trash is not emptied (add --category trash)".to_owned());
    }
    if large > 0 {
        let what = if large == 1 { "1 large file is".to_owned() } else { format!("{large} large files are") };
        parts.push(format!("{what} not included (add --category large-files)"));
    }
    if admin > 0 {
        parts.push(format!("{} administrator access (clean from the desktop app)", needs(admin)));
    }
    format!("not included: {}", parts.join("; "))
}

fn summary(results: &[CleanResult], disk_gain: Option<i64>) -> String {
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
    if let Some(gain) = disk_gain {
        let _ = write!(out, "; free space {} (measured)", format::signed_bytes(gain));
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
    let _ = writeln!(out, "\n{}, {} reclaimable", format::items(findings.len()), format::bytes(total));
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
            "--include-review",
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
                include_review: true,
                large_files: false,
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
            summary(&[r(true, 2_000_000, false), r(true, 3_000_000, true), r(false, 1, false)], None),
            "cleaned 2 items, freed 2.0 MB, 3.0 MB moved to the Trash (empty it to reclaim), 1 not cleaned"
        );
        assert_eq!(
            summary(&[r(true, 2_000_000, false)], Some(1_900_000)),
            "cleaned 1 item, freed 2.0 MB; free space +1.9 MB (measured)"
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

    fn categorized(id: &str, category: Category, risk: Risk) -> Finding {
        let mut f = finding(id, Some(10), true, Privilege::User);
        f.category = category;
        f.risk = risk;
        f
    }

    #[test]
    fn clean_takes_only_safe_items_and_never_the_trash_by_default() {
        let all = vec![
            categorized("cache", Category::DeveloperCaches, Risk::Safe),
            categorized("volumes", Category::Containers, Risk::Review),
            categorized("trash", Category::Trash, Risk::Safe),
            finding("info", Some(1), false, Privilege::User),
        ];
        let opts = parse(&args(&["--yes"])).expect("parse");
        let (chosen, held) = opts.select_for_clean(all.clone(), 0);
        assert_eq!(chosen.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["cache"]);
        let reasons: Vec<_> = held.iter().map(|(f, r)| (f.id.as_str(), *r)).collect();
        assert_eq!(reasons, [("volumes", HeldBack::Review), ("trash", HeldBack::NeedsCategory(Category::Trash))]);
        assert_eq!(
            held_back_note(&held),
            "not included: 1 item is marked Review (add --include-review); the Trash is not emptied (add --category trash)"
        );

        let opts = parse(&args(&["--yes", "--include-review", "--category", "trash", "--category", "containers"]))
            .expect("parse");
        let (chosen, held) = opts.select_for_clean(all, 0);
        assert_eq!(chosen.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["volumes", "trash"]);
        assert!(held.is_empty());
    }

    #[test]
    fn clean_refuses_unreadable_settings() {
        let ok = Loaded { settings: Settings { older_than: Some(3), ..Settings::default() }, problem: None };
        assert_eq!(settings_for_clean(ok).expect("ok").older_than, Some(3));
        let broken =
            Loaded { settings: Settings::default(), problem: Some("settings.json: could not read ignored".into()) };
        let err = settings_for_clean(broken).unwrap_err().to_string();
        assert!(err.contains("refusing to clean") && err.contains("could not read ignored"), "{err}");
    }

    #[test]
    fn admin_items_are_held_back_not_failed() {
        let mut admin = categorized("syslogs", Category::Logs, Risk::Safe);
        admin.privilege = Privilege::Admin;
        let all = vec![admin, categorized("cache", Category::DeveloperCaches, Risk::Safe)];
        let opts = parse(&args(&["--yes", "--include-review"])).expect("parse");
        let (chosen, held) = opts.select_for_clean(all, 0);
        assert_eq!(chosen.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["cache"]);
        assert_eq!(held.iter().map(|(f, r)| (f.id.as_str(), *r)).collect::<Vec<_>>(), [("syslogs", HeldBack::Admin)]);
        assert_eq!(
            held_back_note(&held),
            "not included: 1 item needs administrator access (clean from the desktop app)"
        );
    }

    #[test]
    fn large_files_need_their_category_even_with_include_review() {
        let movie = categorized("movie", Category::LargeFiles, Risk::Review);
        let opts = parse(&args(&["--yes", "--include-review", "--large-files"])).expect("parse");
        assert!(opts.large_files);
        let (chosen, held) = opts.select_for_clean(vec![movie.clone()], 0);
        assert!(chosen.is_empty());
        assert_eq!(held_back_note(&held), "not included: 1 large file is not included (add --category large-files)");
        let opts = parse(&args(&["--yes", "--include-review", "--category", "large-files"])).expect("parse");
        assert_eq!(opts.select_for_clean(vec![movie], 0).0.len(), 1);
    }
}
