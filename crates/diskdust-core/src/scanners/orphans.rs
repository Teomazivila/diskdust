//! Per-app folders left behind by uninstalled apps (macOS): `~/Library/Application Support`,
//! `Saved Application State`, `HTTPStorages` and `WebKit`, keyed by bundle id.

use std::collections::HashSet;
use std::path::Path;

use rayon::prelude::*;

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir};
use crate::model::{Category, CleanupAction, Finding, Os, Risk, SPECIFIC};

#[derive(Debug)]
pub struct OrphanedAppDataScanner;

/// `(folder under ~/Library, suffix after the bundle id, what it holds)`.
const LOCATIONS: [(&str, &str, &str); 4] = [
    ("Library/Application Support", "", "App data"),
    ("Library/Saved Application State", ".savedState", "Saved window state"),
    ("Library/HTTPStorages", "", "Cookies and HTTP cache"),
    ("Library/WebKit", "", "Web content data"),
];

/// Reverse-DNS names such as `com.vendor.app`: at least three dot-separated segments.
fn looks_like_bundle_id(name: &str) -> bool {
    let segments: Vec<_> = name.split('.').collect();
    segments.len() >= 3
        && segments[0].len() >= 2
        && segments[0].bytes().all(|b| b.is_ascii_lowercase())
        && segments
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

fn bundle_id(app: &Path) -> Option<String> {
    let value = plist::Value::from_file(app.join("Contents/Info.plist")).ok()?;
    value.as_dictionary()?.get("CFBundleIdentifier")?.as_string().map(str::to_ascii_lowercase)
}

/// Bundle identifiers of every `.app` directly inside `dirs` (and one folder deeper).
fn installed_bundle_ids(dirs: &[std::path::PathBuf]) -> HashSet<String> {
    let mut apps = Vec::new();
    for dir in dirs {
        for entry in children(dir) {
            if entry.extension().is_some_and(|e| e == "app") {
                apps.push(entry);
            } else if is_real_dir(&entry) {
                apps.extend(children(&entry).into_iter().filter(|p| p.extension().is_some_and(|e| e == "app")));
            }
        }
    }
    apps.par_iter().filter_map(|app| bundle_id(app)).collect()
}

fn is_installed(name: &str, installed: &HashSet<String>) -> bool {
    let name = name.to_ascii_lowercase();
    installed.iter().any(|id| id == &name || id.starts_with(&format!("{name}.")) || name.starts_with(&format!("{id}.")))
}

impl Scanner for OrphanedAppDataScanner {
    fn id(&self) -> &'static str {
        "orphans"
    }

    fn name(&self) -> &'static str {
        "Leftovers of uninstalled apps"
    }

    fn supports(&self, os: Os) -> bool {
        os == Os::MacOs
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let installed = installed_bundle_ids(&ctx.app_dirs);
        if installed.is_empty() {
            // Without a list of installed apps everything would look orphaned; report nothing.
            return Ok(Vec::new());
        }
        Ok(LOCATIONS
            .par_iter()
            .flat_map(|(rel, suffix, what)| {
                let root = ctx.home.join(rel);
                children(&root)
                    .par_iter()
                    .filter(|p| is_real_dir(p))
                    .filter_map(|dir| {
                        let name = file_name(dir);
                        let id = name.strip_suffix(suffix)?;
                        if !looks_like_bundle_id(id) || id.starts_with("com.apple.") || is_installed(id, &installed) {
                            return None;
                        }
                        let report = ctx.measure(dir)?;
                        (report.bytes >= MIN_BYTES).then(|| Finding {
                            last_modified: report.newest,
                            detail: format!(
                                "{what} with no matching installed app. The app may live outside /Applications; \
                                 check before removing."
                            ),
                            path: Some(dir.clone()),
                            bytes: Some(report.bytes),
                            risk: Risk::Review,
                            action: Some(CleanupAction::RemovePath { path: dir.clone(), root: root.clone() }),
                            specificity: SPECIFIC,
                            ..base_finding(
                                "orphans",
                                format!("orphans:{}", dir.display()),
                                Category::OrphanedAppData,
                                if suffix.is_empty() && *rel == "Library/Application Support" {
                                    id.to_owned()
                                } else {
                                    format!("{id} · {what}")
                                },
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};

    fn install_app(env: &Env, rel: &str, id: &str) {
        let contents = env.home.join(rel).join("Contents");
        std::fs::create_dir_all(&contents).expect("mkdir");
        let mut dict = plist::Dictionary::new();
        dict.insert("CFBundleIdentifier".into(), plist::Value::String(id.into()));
        plist::Value::Dictionary(dict).to_file_xml(contents.join("Info.plist")).expect("plist");
    }

    #[test]
    fn bundle_id_shape() {
        assert!(looks_like_bundle_id("com.vendor.app"));
        assert!(looks_like_bundle_id("io.some-vendor.app_2"));
        assert!(!looks_like_bundle_id("Slack"));
        assert!(!looks_like_bundle_id("com.vendor"));
        assert!(!looks_like_bundle_id("Com.vendor.app"));
        assert!(!looks_like_bundle_id("com..app"));
        assert!(!looks_like_bundle_id("c.vendor.app"));
    }

    #[test]
    fn installed_matching_handles_prefixes() {
        let installed: HashSet<String> = ["com.vendor.app".to_owned()].into();
        assert!(is_installed("com.vendor.app", &installed));
        assert!(is_installed("COM.vendor.app", &installed));
        assert!(is_installed("com.vendor.app.helper", &installed));
        assert!(!is_installed("com.vendor.other", &installed));
        let nested: HashSet<String> = ["com.vendor.app.desktop".to_owned()].into();
        assert!(is_installed("com.vendor.app", &nested));
    }

    #[test]
    fn finds_orphans_only() {
        let env = Env::new();
        install_app(&env, "Applications/Kept.app", "com.kept.app");
        install_app(&env, "Applications/Suite/Nested.app", "com.suite.nested");
        env.file("Library/Application Support/com.kept.app/db", BIG);
        env.file("Library/Application Support/com.suite.nested/db", BIG);
        env.file("Library/Application Support/com.gone.app/db", BIG);
        env.file("Library/Application Support/com.apple.something/db", BIG);
        env.file("Library/Application Support/Plain Name/db", BIG);
        env.file("Library/Application Support/com.tiny.app/db", 10);
        let runner = FakeRunner::new();
        let found = OrphanedAppDataScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["com.gone.app"]);
        assert_eq!(found[0].risk, Risk::Review);
    }

    #[test]
    fn other_library_locations_are_checked() {
        let env = Env::new();
        install_app(&env, "Applications/Kept.app", "com.kept.app");
        env.file("Library/Saved Application State/com.gone.app.savedState/data.data", BIG);
        env.file("Library/Saved Application State/com.kept.app.savedState/data.data", BIG);
        env.file("Library/HTTPStorages/com.gone.app/httpstorages.sqlite", BIG);
        env.file("Library/WebKit/com.gone.app/WebsiteData/x", BIG);
        env.file("Library/WebKit/Databases/x", BIG);
        let runner = FakeRunner::new();
        let mut titles: Vec<_> = OrphanedAppDataScanner
            .scan(&env.ctx(Os::MacOs, &runner))
            .expect("scan")
            .into_iter()
            .map(|f| f.title)
            .collect();
        titles.sort();
        assert_eq!(
            titles,
            [
                "com.gone.app · Cookies and HTTP cache",
                "com.gone.app · Saved window state",
                "com.gone.app · Web content data"
            ]
        );
    }

    #[test]
    fn no_installed_apps_means_no_findings() {
        let env = Env::new();
        env.file("Library/Application Support/com.gone.app/db", BIG);
        let runner = FakeRunner::new();
        assert!(OrphanedAppDataScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan").is_empty());
        assert!(!OrphanedAppDataScanner.supports(Os::Linux));
        assert_eq!(OrphanedAppDataScanner.id(), "orphans");
        assert!(!OrphanedAppDataScanner.name().is_empty());
    }
}
