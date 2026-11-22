//! Table-driven scanner for well-known cache, log and data locations.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::{
    MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir, with_shared_note,
};
use crate::model::{Category, CleanupAction, Finding, GENERIC, KnownCommand, Os, Privilege, Risk, SPECIFIC};

/// Where a rule's relative path is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Home,
    System,
}

/// Whether a rule reports the folder as one item or each child separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Whole,
    Children,
}

/// A single well-known location.
#[derive(Debug, Clone)]
pub struct PathRule {
    pub id: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub os: &'static [Os],
    pub base: Base,
    pub rel: &'static str,
    pub mode: Mode,
    pub category: Category,
    pub risk: Risk,
    pub privilege: Privilege,
    /// Clean via this command instead of removing the path.
    pub command: Option<KnownCommand>,
    /// Only applies when this program is installed.
    pub requires: Option<&'static str>,
    /// In [`Mode::Children`], children whose name starts with this prefix are marked
    /// [`Risk::Review`] (e.g. `com.apple.` caches, which macOS services may hold open).
    pub review_prefix: Option<&'static str>,
}

const MAC: &[Os] = &[Os::MacOs];
const LINUX: &[Os] = &[Os::Linux];
const BOTH: &[Os] = &[Os::MacOs, Os::Linux];

impl PathRule {
    const fn new(
        id: &'static str,
        title: &'static str,
        detail: &'static str,
        os: &'static [Os],
        rel: &'static str,
    ) -> Self {
        Self {
            id,
            title,
            detail,
            os,
            base: Base::Home,
            rel,
            mode: Mode::Whole,
            category: Category::DeveloperCaches,
            risk: Risk::Safe,
            privilege: Privilege::User,
            command: None,
            requires: None,
            review_prefix: None,
        }
    }

    const fn children(mut self) -> Self {
        self.mode = Mode::Children;
        self
    }

    const fn category(mut self, category: Category) -> Self {
        self.category = category;
        self
    }

    const fn review(mut self) -> Self {
        self.risk = Risk::Review;
        self
    }

    const fn review_children_starting_with(mut self, prefix: &'static str) -> Self {
        self.review_prefix = Some(prefix);
        self
    }

    const fn system_admin(mut self) -> Self {
        self.base = Base::System;
        self.privilege = Privilege::Admin;
        self
    }

    fn command(mut self, command: KnownCommand, requires: &'static str) -> Self {
        self.command = Some(command);
        self.requires = Some(requires);
        self
    }

    fn specificity(&self) -> u8 {
        if self.mode == Mode::Children { GENERIC } else { SPECIFIC }
    }
}

const APP_CACHE: &str = "Application cache. Apps rebuild it on demand; quit the app first.";
const LOGS: &str = "Old log files. Safe to remove.";
const DEV_CACHE: &str = "Download cache. The tool re-downloads what it needs.";
const ELECTRON_CACHE: &str = "Electron app cache. Quit the app before cleaning.";
const APPLE_CACHE: &str = "Used by macOS system services (iCloud, Spotlight, …), which may hold it open or \
                           rebuild it slowly. Review before removing.";

/// The built-in rule table.
#[allow(clippy::too_many_lines)]
pub fn default_rules() -> Vec<PathRule> {
    use Category as C;
    vec![
        // ---- Generic cache and log folders -------------------------------------------------
        PathRule::new("mac-user-caches", "User cache", APP_CACHE, MAC, "Library/Caches")
            .children()
            .category(C::AppCaches)
            .review_children_starting_with("com.apple."),
        PathRule::new("mac-user-logs", "User log", LOGS, MAC, "Library/Logs").children().category(C::Logs),
        PathRule::new("linux-user-cache", "User cache", APP_CACHE, LINUX, ".cache").children().category(C::AppCaches),
        // ---- Electron / browser caches ----------------------------------------------------
        PathRule::new("slack-cache", "Slack cache", ELECTRON_CACHE, MAC, "Library/Application Support/Slack/Cache")
            .category(C::AppCaches),
        PathRule::new(
            "slack-sw-cache",
            "Slack service worker cache",
            ELECTRON_CACHE,
            MAC,
            "Library/Application Support/Slack/Service Worker/CacheStorage",
        )
        .category(C::AppCaches),
        PathRule::new("vscode-cache", "VS Code cache", ELECTRON_CACHE, MAC, "Library/Application Support/Code/Cache")
            .category(C::AppCaches),
        PathRule::new(
            "vscode-cached-data",
            "VS Code cached data",
            ELECTRON_CACHE,
            MAC,
            "Library/Application Support/Code/CachedData",
        )
        .category(C::AppCaches),
        PathRule::new(
            "vscode-vsix",
            "VS Code extension downloads",
            ELECTRON_CACHE,
            MAC,
            "Library/Application Support/Code/CachedExtensionVSIXs",
        )
        .category(C::AppCaches),
        PathRule::new("cursor-cache", "Cursor cache", ELECTRON_CACHE, MAC, "Library/Application Support/Cursor/Cache")
            .category(C::AppCaches),
        PathRule::new(
            "cursor-cached-data",
            "Cursor cached data",
            ELECTRON_CACHE,
            MAC,
            "Library/Application Support/Cursor/CachedData",
        )
        .category(C::AppCaches),
        PathRule::new(
            "discord-cache",
            "Discord cache",
            ELECTRON_CACHE,
            MAC,
            "Library/Application Support/discord/Cache",
        )
        .category(C::AppCaches),
        PathRule::new(
            "chrome-sw-cache",
            "Chrome service worker cache",
            "Browser cache. Quit Chrome before cleaning.",
            MAC,
            "Library/Application Support/Google/Chrome/Default/Service Worker/CacheStorage",
        )
        .category(C::AppCaches),
        PathRule::new("linux-slack-cache", "Slack cache", ELECTRON_CACHE, LINUX, ".config/Slack/Cache")
            .category(C::AppCaches),
        PathRule::new(
            "linux-slack-sw-cache",
            "Slack service worker cache",
            ELECTRON_CACHE,
            LINUX,
            ".config/Slack/Service Worker/CacheStorage",
        )
        .category(C::AppCaches),
        PathRule::new("linux-vscode-cache", "VS Code cache", ELECTRON_CACHE, LINUX, ".config/Code/Cache")
            .category(C::AppCaches),
        PathRule::new(
            "linux-vscode-cached-data",
            "VS Code cached data",
            ELECTRON_CACHE,
            LINUX,
            ".config/Code/CachedData",
        )
        .category(C::AppCaches),
        PathRule::new(
            "linux-vscode-vsix",
            "VS Code extension downloads",
            ELECTRON_CACHE,
            LINUX,
            ".config/Code/CachedExtensionVSIXs",
        )
        .category(C::AppCaches),
        PathRule::new("linux-discord-cache", "Discord cache", ELECTRON_CACHE, LINUX, ".config/discord/Cache")
            .category(C::AppCaches),
        PathRule::new(
            "linux-chrome-sw-cache",
            "Chrome service worker cache",
            "Browser cache. Quit Chrome before cleaning.",
            LINUX,
            ".config/google-chrome/Default/Service Worker/CacheStorage",
        )
        .category(C::AppCaches),
        // ---- Developer caches ---------------------------------------------------------------
        PathRule::new(
            "cargo-registry",
            "Cargo registry",
            "Downloaded crate sources and index. Cargo re-downloads on the next build.",
            BOTH,
            ".cargo/registry",
        ),
        PathRule::new(
            "cargo-git",
            "Cargo git checkouts",
            "Git dependencies fetched by Cargo. Re-fetched on the next build.",
            BOTH,
            ".cargo/git",
        ),
        PathRule::new("npm-cache", "npm cache", DEV_CACHE, BOTH, ".npm/_cacache"),
        PathRule::new("yarn-berry-cache", "Yarn Berry cache", DEV_CACHE, BOTH, ".yarn/berry/cache"),
        PathRule::new("yarn-cache-mac", "Yarn cache", DEV_CACHE, MAC, "Library/Caches/Yarn"),
        PathRule::new("yarn-cache-linux", "Yarn cache", DEV_CACHE, LINUX, ".cache/yarn"),
        PathRule::new(
            "pnpm-store-mac",
            "pnpm store",
            "Content-addressed package store. Existing node_modules keep working (hard links).",
            MAC,
            "Library/pnpm/store",
        ),
        PathRule::new(
            "pnpm-store-linux",
            "pnpm store",
            "Content-addressed package store. Existing node_modules keep working (hard links).",
            LINUX,
            ".local/share/pnpm/store",
        ),
        PathRule::new("bun-cache", "Bun cache", DEV_CACHE, BOTH, ".bun/install/cache"),
        PathRule::new("pip-cache-mac", "pip cache", DEV_CACHE, MAC, "Library/Caches/pip"),
        PathRule::new("pip-cache-linux", "pip cache", DEV_CACHE, LINUX, ".cache/pip"),
        PathRule::new("uv-cache", "uv cache", DEV_CACHE, BOTH, ".cache/uv"),
        PathRule::new("gradle-caches", "Gradle caches", DEV_CACHE, BOTH, ".gradle/caches"),
        PathRule::new(
            "gradle-wrapper",
            "Gradle wrapper distributions",
            "Downloaded Gradle versions. Re-downloaded by ./gradlew when needed.",
            BOTH,
            ".gradle/wrapper/dists",
        ),
        PathRule::new("maven-repo", "Maven local repository", DEV_CACHE, BOTH, ".m2/repository"),
        PathRule::new("helm-cache-mac", "Helm cache", DEV_CACHE, MAC, "Library/Caches/helm"),
        PathRule::new("helm-cache-linux", "Helm cache", DEV_CACHE, LINUX, ".cache/helm"),
        PathRule::new("deno-cache-mac", "Deno cache", DEV_CACHE, MAC, "Library/Caches/deno"),
        PathRule::new("deno-cache-linux", "Deno cache", DEV_CACHE, LINUX, ".cache/deno"),
        PathRule::new(
            "playwright-mac",
            "Playwright browsers",
            "Downloaded test browsers. Reinstall with `npx playwright install`.",
            MAC,
            "Library/Caches/ms-playwright",
        ),
        PathRule::new(
            "playwright-linux",
            "Playwright browsers",
            "Downloaded test browsers. Reinstall with `npx playwright install`.",
            LINUX,
            ".cache/ms-playwright",
        ),
        PathRule::new("cocoapods-cache", "CocoaPods cache", DEV_CACHE, MAC, "Library/Caches/CocoaPods"),
        PathRule::new(
            "jetbrains-cache-mac",
            "JetBrains IDE caches",
            "IDE indexes and caches. Rebuilt on next launch (first open is slower).",
            MAC,
            "Library/Caches/JetBrains",
        ),
        PathRule::new(
            "jetbrains-cache-linux",
            "JetBrains IDE caches",
            "IDE indexes and caches. Rebuilt on next launch (first open is slower).",
            LINUX,
            ".cache/JetBrains",
        ),
        PathRule::new("terraform-plugin-cache", "Terraform plugin cache", DEV_CACHE, BOTH, ".terraform.d/plugin-cache"),
        PathRule::new("minikube-cache", "minikube cache", DEV_CACHE, BOTH, ".minikube/cache"),
        PathRule::new(
            "huggingface",
            "Hugging Face cache",
            "Downloaded models and datasets. Large to re-download.",
            BOTH,
            ".cache/huggingface",
        )
        .review(),
        PathRule::new(
            "ollama-models",
            "Ollama models",
            "Local LLM models. Re-pull with `ollama pull` if needed again.",
            BOTH,
            ".ollama/models",
        )
        .review(),
        // ---- Xcode ----------------------------------------------------------------------
        PathRule::new(
            "xcode-derived-data",
            "Xcode DerivedData",
            "Build intermediates and indexes. Xcode rebuilds them.",
            MAC,
            "Library/Developer/Xcode/DerivedData",
        )
        .category(C::Xcode),
        PathRule::new(
            "xcode-archives",
            "Xcode archive",
            "Archived app builds. Needed to symbolicate crash reports of shipped versions.",
            MAC,
            "Library/Developer/Xcode/Archives",
        )
        .children()
        .category(C::Xcode)
        .review(),
        PathRule::new(
            "xcode-ios-device-support",
            "iOS device support",
            "Debug symbols for connected devices. Re-created when a device connects.",
            MAC,
            "Library/Developer/Xcode/iOS DeviceSupport",
        )
        .children()
        .category(C::Xcode),
        PathRule::new(
            "xcode-watchos-device-support",
            "watchOS device support",
            "Debug symbols for connected devices. Re-created when a device connects.",
            MAC,
            "Library/Developer/Xcode/watchOS DeviceSupport",
        )
        .children()
        .category(C::Xcode),
        PathRule::new(
            "xcode-tvos-device-support",
            "tvOS device support",
            "Debug symbols for connected devices. Re-created when a device connects.",
            MAC,
            "Library/Developer/Xcode/tvOS DeviceSupport",
        )
        .children()
        .category(C::Xcode),
        PathRule::new(
            "coresimulator-caches",
            "Simulator caches",
            "CoreSimulator dyld caches. Rebuilt on demand.",
            MAC,
            "Library/Developer/CoreSimulator/Caches",
        )
        .category(C::Xcode),
        // ---- Device backups ---------------------------------------------------------------
        PathRule::new(
            "ios-backups",
            "iPhone/iPad backup",
            "Local device backup made by Finder. Only remove if you have another backup.",
            MAC,
            "Library/Application Support/MobileSync/Backup",
        )
        .children()
        .category(C::Backups)
        .review(),
        // ---- System (admin) ---------------------------------------------------------------
        PathRule::new(
            "mac-system-caches",
            "System cache",
            "System-wide application cache. Rebuilt on demand. Removed permanently.",
            MAC,
            "Library/Caches",
        )
        .children()
        .review_children_starting_with("com.apple.")
        .category(C::System)
        .system_admin(),
        PathRule::new(
            "mac-system-logs",
            "System log",
            "System-wide log files. Removed permanently.",
            MAC,
            "Library/Logs",
        )
        .children()
        .category(C::Logs)
        .system_admin(),
        PathRule::new(
            "apt-cache",
            "APT package cache",
            "Downloaded .deb files. Cleaned with `apt-get clean`.",
            LINUX,
            "var/cache/apt/archives",
        )
        .category(C::System)
        .system_admin()
        .command(KnownCommand::AptClean, "apt-get"),
        PathRule::new(
            "dnf-cache",
            "DNF package cache",
            "Downloaded packages and metadata. Cleaned with `dnf clean all`.",
            LINUX,
            "var/cache/dnf",
        )
        .category(C::System)
        .system_admin()
        .command(KnownCommand::DnfClean, "dnf"),
        PathRule::new(
            "dnf5-cache",
            "DNF5 package cache",
            "Downloaded packages and metadata (DNF5, Fedora 41+). Cleaned with `dnf clean all`.",
            LINUX,
            "var/cache/libdnf5",
        )
        .category(C::System)
        .system_admin()
        .command(KnownCommand::DnfClean, "dnf"),
        PathRule::new(
            "pacman-cache",
            "pacman package cache",
            "Cached packages of uninstalled software. Cleaned with `pacman -Sc`.",
            LINUX,
            "var/cache/pacman/pkg",
        )
        .category(C::System)
        .system_admin()
        .command(KnownCommand::PacmanClean, "pacman"),
    ]
}

/// Scanner that evaluates a [`PathRule`] table.
#[derive(Debug)]
pub struct PathRulesScanner {
    rules: Vec<PathRule>,
}

impl PathRulesScanner {
    pub fn new(rules: Vec<PathRule>) -> Self {
        Self { rules }
    }

    fn applies(rule: &PathRule, ctx: &ScanContext<'_>) -> bool {
        rule.os.contains(&ctx.os) && rule.requires.is_none_or(|p| ctx.runner.exists(p))
    }

    fn target(rule: &PathRule, ctx: &ScanContext<'_>) -> PathBuf {
        match rule.base {
            Base::Home => ctx.home.join(rule.rel),
            Base::System => ctx.system_root.join(rule.rel),
        }
    }

    /// Targets of the applicable whole-folder rules. Generic children rules skip these folders,
    /// which would otherwise be walked twice only to be dropped by overlap de-duplication.
    fn claimed(&self, ctx: &ScanContext<'_>) -> HashSet<PathBuf> {
        self.rules
            .iter()
            .filter(|r| r.mode == Mode::Whole && Self::applies(r, ctx))
            .map(|r| Self::target(r, ctx))
            .collect()
    }

    fn scan_rule(rule: &PathRule, ctx: &ScanContext<'_>, claimed: &HashSet<PathBuf>) -> Vec<Finding> {
        if !Self::applies(rule, ctx) {
            return Vec::new();
        }
        let target = Self::target(rule, ctx);
        if !is_real_dir(&target) {
            return Vec::new();
        }
        match rule.mode {
            Mode::Whole => {
                let root = target.parent().map_or_else(|| target.clone(), Path::to_path_buf);
                Self::finding(rule, ctx, &target, &root, rule.title.to_owned(), rule.detail.to_owned())
                    .into_iter()
                    .collect()
            }
            Mode::Children => children(&target)
                .par_iter()
                .filter(|child| !claimed.contains(*child))
                .filter_map(|child| {
                    let name = file_name(child);
                    let detail = format!("{} · {}", rule.title, rule.detail);
                    let mut finding = Self::finding(rule, ctx, child, &target, name.clone(), detail)?;
                    if rule.review_prefix.is_some_and(|prefix| name.starts_with(prefix)) {
                        finding.risk = Risk::Review;
                        finding.detail = format!("{} · {APPLE_CACHE}", rule.title);
                    }
                    Some(finding)
                })
                .collect(),
        }
    }

    fn finding(
        rule: &PathRule,
        ctx: &ScanContext<'_>,
        path: &Path,
        root: &Path,
        title: String,
        detail: String,
    ) -> Option<Finding> {
        if ctx.is_cancelled() {
            return None;
        }
        let report = ctx.measure(path)?;
        if report.bytes < MIN_BYTES {
            return None;
        }
        let action = match &rule.command {
            Some(cmd) => CleanupAction::Run(cmd.clone()),
            None => CleanupAction::RemovePath { path: path.to_path_buf(), root: root.to_path_buf() },
        };
        Some(Finding {
            detail: with_shared_note(detail, &report),
            path: Some(path.to_path_buf()),
            bytes: Some(report.bytes),
            last_modified: report.newest,
            risk: rule.risk,
            privilege: rule.privilege,
            action: Some(action),
            specificity: rule.specificity(),
            ..base_finding("paths", format!("{}:{}", rule.id, path.display()), rule.category, title)
        })
    }
}

impl Scanner for PathRulesScanner {
    fn id(&self) -> &'static str {
        "paths"
    }

    fn name(&self) -> &'static str {
        "Caches, logs and app data"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let claimed = self.claimed(ctx);
        Ok(self.rules.par_iter().flat_map(|rule| Self::scan_rule(rule, ctx, &claimed)).collect())
    }
}

/// Paths of every rule for the given OS, resolved against `home` (used for diagnostics/tests).
pub fn resolved_rule_paths(rules: &[PathRule], os: Os, home: &Path, system_root: &Path) -> Vec<PathBuf> {
    rules
        .iter()
        .filter(|r| r.os.contains(&os))
        .map(|r| match r.base {
            Base::Home => home.join(r.rel),
            Base::System => system_root.join(r.rel),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};

    fn scan(env: &Env, os: Os, runner: &FakeRunner) -> Vec<Finding> {
        let mut found = PathRulesScanner::new(default_rules()).scan(&env.ctx(os, runner)).expect("scan");
        found.sort_by(|a, b| a.id.cmp(&b.id));
        found
    }

    #[test]
    fn rule_ids_unique_and_relative() {
        let rules = default_rules();
        let mut ids: Vec<_> = rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), rules.len());
        assert!(rules.iter().all(|r| !r.rel.starts_with('/') && !r.rel.contains("..")));
        assert!(rules.iter().all(|r| !r.os.is_empty() && !r.title.is_empty() && !r.detail.is_empty()));
    }

    #[test]
    fn mac_cache_children_reported_individually() {
        let env = Env::new();
        env.file("Library/Caches/com.spotify.client/data", BIG);
        env.file("Library/Caches/tiny/data", 10);
        let runner = FakeRunner::new();
        let found = scan(&env, Os::MacOs, &runner);
        assert_eq!(found.len(), 1, "{found:#?}");
        let f = &found[0];
        assert_eq!(f.title, "com.spotify.client");
        assert_eq!(f.category, Category::AppCaches);
        assert_eq!(f.specificity, GENERIC);
        assert_eq!(f.risk, Risk::Safe);
        assert_eq!(
            f.action,
            Some(CleanupAction::RemovePath {
                path: env.home.join("Library/Caches/com.spotify.client"),
                root: env.home.join("Library/Caches"),
            })
        );
        assert!(f.bytes.expect("size") >= BIG as u64);
    }

    #[test]
    fn apple_caches_need_review() {
        let env = Env::new();
        env.file("Library/Caches/com.apple.bird/data", BIG);
        env.file("Library/Caches/com.vendor.app/data", BIG);
        env.sys_file("Library/Caches/com.apple.iconservices.store/data", BIG);
        let runner = FakeRunner::new();
        let found = scan(&env, Os::MacOs, &runner);
        let risks: Vec<_> = found.iter().map(|f| (f.title.as_str(), f.risk)).collect();
        assert_eq!(
            risks,
            [
                ("com.apple.iconservices.store", Risk::Review),
                ("com.apple.bird", Risk::Review),
                ("com.vendor.app", Risk::Safe),
            ]
        );
        assert!(found[1].detail.contains("macOS system services"));
    }

    #[test]
    fn generic_rules_skip_folders_claimed_by_specific_rules() {
        let env = Env::new();
        env.file(".cache/pip/http/a", BIG);
        env.file(".cache/other/x", BIG);
        let runner = FakeRunner::new();
        let scanner = PathRulesScanner::new(default_rules());
        let ctx = env.ctx(Os::Linux, &runner);
        assert!(scanner.claimed(&ctx).contains(&env.home.join(".cache/pip")));
        assert!(!scanner.claimed(&ctx).contains(&env.home.join("var/cache/apt/archives")), "needs apt-get");
        let ids: Vec<_> = scan(&env, Os::Linux, &runner).into_iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(ids.iter().any(|id| id.starts_with("linux-user-cache:") && id.ends_with("other")));
        assert!(ids.iter().any(|id| id.starts_with("pip-cache-linux:")));
    }

    #[test]
    fn whole_rule_uses_parent_as_root() {
        let env = Env::new();
        env.file(".cargo/registry/cache/index/crate.crate", BIG);
        let runner = FakeRunner::new();
        let found = scan(&env, Os::Linux, &runner);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "Cargo registry");
        assert_eq!(found[0].specificity, SPECIFIC);
        assert_eq!(
            found[0].action,
            Some(CleanupAction::RemovePath { path: env.home.join(".cargo/registry"), root: env.home.join(".cargo") })
        );
    }

    #[test]
    fn os_filter_applies() {
        let env = Env::new();
        env.file("Library/Caches/app/x", BIG);
        let runner = FakeRunner::new();
        assert!(scan(&env, Os::Linux, &runner).is_empty());
        env.file(".cache/app/x", BIG);
        let linux = scan(&env, Os::Linux, &runner);
        assert_eq!(linux.len(), 1);
        assert_eq!(linux[0].path.as_deref(), Some(env.home.join(".cache/app").as_path()));
    }

    #[test]
    fn review_rules_are_marked() {
        let env = Env::new();
        env.file(".ollama/models/blobs/sha", BIG);
        let runner = FakeRunner::new();
        let found = scan(&env, Os::MacOs, &runner);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].risk, Risk::Review);
    }

    #[test]
    fn system_rules_are_admin_and_command_rules_need_program() {
        let env = Env::new();
        env.sys_file("var/cache/apt/archives/pkg.deb", BIG);
        let without_apt = FakeRunner::new();
        assert!(scan(&env, Os::Linux, &without_apt).is_empty());
        let with_apt = FakeRunner::new().installed("apt-get");
        let found = scan(&env, Os::Linux, &with_apt);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].privilege, Privilege::Admin);
        assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::AptClean)));
    }

    #[test]
    fn dnf5_cache_is_covered() {
        let env = Env::new();
        env.sys_file("var/cache/libdnf5/fedora-abc/packages/x.rpm", BIG);
        let runner = FakeRunner::new().installed("dnf");
        let found = scan(&env, Os::Linux, &runner);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "DNF5 package cache");
        assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::DnfClean)));
    }

    #[test]
    fn mac_system_caches_are_admin_children() {
        let env = Env::new();
        env.sys_file("Library/Caches/com.vendor.updater/blob", BIG);
        let runner = FakeRunner::new();
        let found = scan(&env, Os::MacOs, &runner);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].privilege, Privilege::Admin);
        assert_eq!(found[0].category, Category::System);
    }

    #[test]
    fn symlinked_rule_targets_are_ignored() {
        let env = Env::new();
        let elsewhere = env.file("elsewhere/data", BIG);
        std::fs::create_dir_all(env.home.join(".cargo")).expect("mkdir");
        std::os::unix::fs::symlink(elsewhere.parent().expect("parent"), env.home.join(".cargo/registry"))
            .expect("symlink");
        let runner = FakeRunner::new();
        assert!(scan(&env, Os::MacOs, &runner).is_empty());
    }

    #[test]
    fn cancelled_scan_returns_nothing() {
        let env = Env::new();
        env.file(".cargo/registry/x", BIG);
        env.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let runner = FakeRunner::new();
        assert!(scan(&env, Os::MacOs, &runner).is_empty());
    }

    #[test]
    fn resolved_paths_respect_os_and_base() {
        let rules = default_rules();
        let paths = resolved_rule_paths(&rules, Os::Linux, Path::new("/h"), Path::new("/s"));
        assert!(paths.contains(&PathBuf::from("/h/.cache")));
        assert!(paths.contains(&PathBuf::from("/s/var/cache/apt/archives")));
        assert!(!paths.contains(&PathBuf::from("/h/Library/Caches")));
        let scanner = PathRulesScanner::new(Vec::new());
        assert_eq!(scanner.id(), "paths");
        assert!(scanner.supports(Os::Linux));
    }
}
