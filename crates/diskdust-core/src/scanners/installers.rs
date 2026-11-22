//! Installers that are rarely needed again: `Install macOS …` apps and old disk images or
//! packages in Downloads.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir};
use crate::model::{Category, CleanupAction, Finding, Os, SPECIFIC};

/// Downloads younger than this are left alone (they may still be in use).
pub const DOWNLOAD_MIN_AGE: Duration = Duration::from_hours(30 * 24);

#[derive(Debug)]
pub struct InstallersScanner;

const fn installer_extensions(os: Os) -> &'static [&'static str] {
    match os {
        Os::MacOs => &["dmg", "pkg", "iso"],
        Os::Linux => &["iso", "deb", "rpm", "appimage"],
    }
}

fn unix_secs(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_secs()).ok())
}

fn macos_installer_apps(ctx: &ScanContext<'_>) -> Vec<Finding> {
    let apps = ctx.system_path("/Applications");
    children(&apps)
        .into_iter()
        .filter(|p| {
            let name = file_name(p);
            (name.starts_with("Install macOS ") || name.starts_with("Install OS X "))
                && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("app"))
        })
        .filter(|p| is_real_dir(p))
        .filter_map(|app| {
            let report = ctx.measure(&app)?;
            (report.bytes >= MIN_BYTES).then(|| Finding {
                detail: "macOS installer. Download it again from the App Store or with \
                         `softwareupdate --fetch-full-installer` if you need it."
                    .to_owned(),
                path: Some(app.clone()),
                bytes: Some(report.bytes),
                last_modified: report.newest,
                action: Some(CleanupAction::RemovePath { path: app.clone(), root: apps.clone() }),
                specificity: SPECIFIC,
                ..base_finding(
                    "installers",
                    format!("installers:{}", app.display()),
                    Category::Installers,
                    file_name(&app),
                )
            })
        })
        .collect()
}

fn old_downloads(ctx: &ScanContext<'_>, downloads: &Path, cutoff: SystemTime) -> Vec<Finding> {
    let extensions = installer_extensions(ctx.os);
    children(downloads)
        .into_iter()
        .filter(|p| {
            p.extension().is_some_and(|e| extensions.contains(&e.to_string_lossy().to_ascii_lowercase().as_str()))
        })
        .filter_map(|file| {
            let meta = std::fs::symlink_metadata(&file).ok().filter(std::fs::Metadata::is_file)?;
            let modified = meta.modified().ok().filter(|m| *m < cutoff)?;
            let bytes = crate::size::allocated_bytes(&meta);
            (bytes >= MIN_BYTES).then(|| Finding {
                detail: "Installer or disk image in Downloads, untouched for over 30 days. Usually not needed once \
                         installed."
                    .to_owned(),
                path: Some(file.clone()),
                bytes: Some(bytes),
                last_modified: unix_secs(modified),
                action: Some(CleanupAction::RemovePath { path: file.clone(), root: downloads.to_path_buf() }),
                specificity: SPECIFIC,
                ..base_finding(
                    "installers",
                    format!("installers:{}", file.display()),
                    Category::Installers,
                    file_name(&file),
                )
            })
        })
        .collect()
}

impl Scanner for InstallersScanner {
    fn id(&self) -> &'static str {
        "installers"
    }

    fn name(&self) -> &'static str {
        "Installers and disk images"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let mut found = if ctx.os == Os::MacOs { macos_installer_apps(ctx) } else { Vec::new() };
        let cutoff = SystemTime::now().checked_sub(DOWNLOAD_MIN_AGE).unwrap_or(UNIX_EPOCH);
        found.extend(old_downloads(ctx, &ctx.home.join("Downloads"), cutoff));
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::model::Risk;
    use crate::scanners::testutil::{BIG, Env};

    fn age(path: &Path, days: u64) {
        let file = std::fs::File::options().write(true).open(path).expect("open");
        file.set_modified(SystemTime::now() - Duration::from_hours(days * 24)).expect("mtime");
    }

    #[test]
    fn old_installers_in_downloads() {
        let env = Env::new();
        let old_dmg = env.file("Downloads/Tool-1.2.DMG", BIG);
        let old_pdf = env.file("Downloads/paper.pdf", BIG);
        let recent = env.file("Downloads/new.pkg", BIG);
        let tiny = env.file("Downloads/tiny.iso", 10);
        for p in [&old_dmg, &old_pdf, &tiny] {
            age(p, 45);
        }
        age(&recent, 3);
        let runner = FakeRunner::new();
        let found = InstallersScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["Tool-1.2.DMG"]);
        assert_eq!(found[0].risk, Risk::Review);
        assert_eq!(found[0].category, Category::Installers);
        assert!(found[0].last_modified.is_some());
        assert_eq!(
            found[0].action,
            Some(CleanupAction::RemovePath { path: old_dmg, root: env.home.join("Downloads") })
        );
    }

    #[test]
    fn linux_extensions_and_mac_installer_apps() {
        let env = Env::new();
        let image = env.file("Downloads/tool.AppImage", BIG);
        age(&image, 60);
        let dmg = env.file("Downloads/mac.dmg", BIG);
        age(&dmg, 60);
        let runner = FakeRunner::new();
        let linux = InstallersScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(linux.iter().map(|f| f.title.as_str()).collect::<Vec<_>>(), ["tool.AppImage"]);

        env.sys_file("Applications/Install macOS Sequoia.app/Contents/SharedSupport/SharedSupport.dmg", BIG);
        env.sys_file("Applications/Installer Helper.app/Contents/x", BIG);
        let mac = InstallersScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        let titles: Vec<_> = mac.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["Install macOS Sequoia.app", "mac.dmg"]);
        assert!(InstallersScanner.supports(Os::Linux) && InstallersScanner.id() == "installers");
        assert!(!InstallersScanner.name().is_empty());
    }
}
