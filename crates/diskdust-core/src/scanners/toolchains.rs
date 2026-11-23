//! Old versions of developer toolchains: rustup toolchains, Node versions (nvm, fnm), pyenv
//! Pythons, older `JetBrains` IDE settings and Android system images.
//!
//! Everything here is `Review`: a version that is not the default may still be pinned by a
//! project. The version each manager treats as the default is always kept.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir};
use crate::model::{Category, CleanupAction, Finding, KnownCommand, Os, SPECIFIC};

#[derive(Debug)]
pub struct ToolchainsScanner;

impl Scanner for ToolchainsScanner {
    fn id(&self) -> &'static str {
        "toolchains"
    }

    fn name(&self) -> &'static str {
        "Old developer toolchains"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        // Each tool is independent: one failing (e.g. rustup timing out) must not hide the others.
        let mut found = rustup(ctx);
        found.extend(nvm(ctx));
        found.extend(fnm(ctx));
        found.extend(pyenv(ctx));
        found.extend(jetbrains(ctx));
        found.extend(android_images(ctx));
        Ok(found)
    }
}

/// Measures `path` and builds a `Review` finding, or `None` when small or cancelled.
fn finding(
    ctx: &ScanContext<'_>,
    id: String,
    title: String,
    path: &Path,
    action: CleanupAction,
    detail: &str,
) -> Option<Finding> {
    let report = ctx.measure(path)?;
    (report.bytes >= MIN_BYTES).then(|| Finding {
        detail: detail.to_owned(),
        path: Some(path.to_path_buf()),
        bytes: Some(report.bytes),
        last_modified: report.newest,
        action: Some(action),
        specificity: SPECIFIC,
        ..base_finding("toolchains", id, Category::Toolchains, title)
    })
}

// ---- rustup -------------------------------------------------------------------------------

/// Parses `rustup toolchain list`, returning toolchains that are neither default, active nor an
/// override. Lines look like `stable-aarch64-apple-darwin (active, default)`,
/// `1.94.0-aarch64-apple-darwin`, or (older rustup) `1.70.0-x86_64-unknown-linux-gnu (override)`.
fn removable_rustup_toolchains(list: &str) -> Vec<String> {
    list.lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, flags) = line.split_once(' ').unwrap_or((line, ""));
            let keep = ["default", "active", "override"].iter().any(|flag| flags.contains(flag));
            (!name.is_empty() && !keep).then(|| name.to_owned())
        })
        .collect()
}

fn rustup(ctx: &ScanContext<'_>) -> Vec<Finding> {
    if !ctx.runner.exists("rustup") {
        return Vec::new();
    }
    let argv: Vec<String> = ["rustup", "toolchain", "list"].iter().map(|s| (*s).to_owned()).collect();
    let out = match ctx.runner.run(&argv, Duration::from_secs(30)) {
        Ok(out) if out.success => out,
        Ok(out) => {
            tracing::warn!(stderr = %out.stderr.trim(), "rustup toolchain list failed; skipping Rust toolchains");
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not run rustup; skipping Rust toolchains");
            return Vec::new();
        }
    };
    let dir = ctx.home.join(".rustup/toolchains");
    removable_rustup_toolchains(&out.stdout)
        .into_iter()
        .filter_map(|toolchain| {
            let cmd = KnownCommand::RustupUninstall { toolchain: toolchain.clone() };
            let path = dir.join(&toolchain);
            if !cmd.is_well_formed() || !is_real_dir(&path) {
                return None;
            }
            finding(
                ctx,
                format!("toolchains:rustup:{toolchain}"),
                format!("Rust {toolchain}"),
                &path,
                CleanupAction::Run(cmd),
                "Rust toolchain that is neither the default nor active. Removed with `rustup toolchain uninstall`; \
                 projects that pin it (rust-toolchain.toml) reinstall it on their next build.",
            )
        })
        .collect()
}

// ---- Node (nvm, fnm) -----------------------------------------------------------------------

/// Numeric version from names like `v20.11.1` or `20.11.1`.
fn version_key(name: &str) -> Vec<u64> {
    name.trim_start_matches('v').split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn newest<'a>(names: impl IntoIterator<Item = &'a String>) -> Option<&'a String> {
    names.into_iter().max_by_key(|n| version_key(n))
}

/// Resolves an nvm alias (`v20.11.1`, `20`, `node`, `lts/*`, `lts/iron`, `default`) to an installed
/// version folder name, following alias files up to a few levels.
fn resolve_nvm_alias(alias: &str, installed: &[String], alias_dir: &Path, depth: u8) -> Option<String> {
    let alias = alias.trim();
    if depth > 4 || alias.is_empty() {
        return None;
    }
    if alias == "node" || alias == "stable" {
        return newest(installed).cloned();
    }
    if let Some(name) = alias.strip_prefix("lts/") {
        let file = if name == "*" { alias_dir.join("lts/*") } else { alias_dir.join("lts").join(name) };
        let next = std::fs::read_to_string(file).ok()?;
        return resolve_nvm_alias(&next, installed, alias_dir, depth + 1);
    }
    let wanted = format!("v{}", alias.trim_start_matches('v'));
    if installed.contains(&wanted) {
        return Some(wanted);
    }
    let prefix = format!("{wanted}.");
    let matching: Vec<&String> = installed.iter().filter(|v| v.starts_with(&prefix)).collect();
    if let Some(best) = newest(matching) {
        return Some(best.clone());
    }
    let next = std::fs::read_to_string(alias_dir.join(alias)).ok()?;
    resolve_nvm_alias(&next, installed, alias_dir, depth + 1)
}

fn version_dirs(dir: &Path) -> Vec<(String, PathBuf)> {
    children(dir).into_iter().filter(|p| is_real_dir(p)).map(|p| (file_name(&p), p)).collect()
}

fn nvm(ctx: &ScanContext<'_>) -> Vec<Finding> {
    let nvm_dir = ctx.home.join(".nvm");
    let versions_dir = nvm_dir.join("versions/node");
    let versions = version_dirs(&versions_dir);
    let names: Vec<String> = versions.iter().map(|(n, _)| n.clone()).collect();
    let alias_dir = nvm_dir.join("alias");
    let default = std::fs::read_to_string(alias_dir.join("default"))
        .ok()
        .and_then(|a| resolve_nvm_alias(&a, &names, &alias_dir, 0))
        .or_else(|| newest(&names).cloned());
    versions
        .iter()
        .filter(|(name, _)| Some(name) != default.as_ref())
        .filter_map(|(name, path)| {
            finding(
                ctx,
                format!("toolchains:nvm:{name}"),
                format!("Node {name} (nvm)"),
                path,
                CleanupAction::RemovePath { path: path.clone(), root: versions_dir.clone() },
                "Node.js version installed with nvm that is not your default. Reinstall with `nvm install` if a \
                 project needs it.",
            )
        })
        .collect()
}

fn fnm_dirs(ctx: &ScanContext<'_>) -> Vec<PathBuf> {
    let mut dirs = vec![ctx.home.join(".local/share/fnm"), ctx.home.join(".fnm")];
    if ctx.os == Os::MacOs {
        dirs.push(ctx.home.join("Library/Application Support/fnm"));
    }
    dirs.into_iter().filter(|d| is_real_dir(&d.join("node-versions"))).collect()
}

fn fnm(ctx: &ScanContext<'_>) -> Vec<Finding> {
    fnm_dirs(ctx)
        .into_iter()
        .flat_map(|base| {
            let versions_dir = base.join("node-versions");
            let versions = version_dirs(&versions_dir);
            // fnm aliases (`default`, …) are symlinks into node-versions/<version>/.
            let canonical_versions = versions_dir.canonicalize().unwrap_or_else(|_| versions_dir.clone());
            let mut keep: HashSet<String> = std::fs::read_dir(base.join("aliases"))
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter_map(|alias| alias.path().canonicalize().ok())
                .filter_map(|target| {
                    target
                        .strip_prefix(&canonical_versions)
                        .ok()?
                        .components()
                        .next()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                })
                .collect();
            if keep.is_empty() {
                let names: Vec<String> = versions.iter().map(|(n, _)| n.clone()).collect();
                keep.extend(newest(&names).cloned());
            }
            versions
                .iter()
                .filter(|(name, _)| !keep.contains(name))
                .filter_map(|(name, path)| {
                    finding(
                        ctx,
                        format!("toolchains:fnm:{name}"),
                        format!("Node {name} (fnm)"),
                        path,
                        CleanupAction::RemovePath { path: path.clone(), root: versions_dir.clone() },
                        "Node.js version installed with fnm that no alias points to. Reinstall with `fnm install` \
                         if a project needs it.",
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

// ---- pyenv ---------------------------------------------------------------------------------

/// Version names selected in a pyenv `version` file: whitespace-separated, `#` starts a
/// comment, `system` means the OS Python.
fn pyenv_selected(text: &str) -> Vec<String> {
    text.lines()
        .flat_map(|line| line.split('#').next().unwrap_or_default().split_whitespace())
        .filter(|name| *name != "system")
        .map(str::to_owned)
        .collect()
}

/// Installed versions that the selected names depend on, or `None` when a name cannot be
/// resolved (then nothing is offered: a wrong guess would delete the Python you use).
///
/// - an installed version keeps itself;
/// - a pyenv-virtualenv name (`versions/<env>` → `versions/<base>/envs/<env>`) keeps its base;
/// - a prefix such as `3.12`, which pyenv resolves to an installed `3.12.x`, keeps every match.
fn pyenv_keep(versions_dir: &Path, installed: &[String], selected: &[String]) -> Option<HashSet<String>> {
    let canonical_versions = versions_dir.canonicalize().ok()?;
    let mut keep = HashSet::new();
    for name in selected {
        let before = keep.len();
        if let Ok(resolved) = versions_dir.join(name).canonicalize()
            && let Ok(rel) = resolved.strip_prefix(&canonical_versions)
            && let Some(base) = rel.components().next()
        {
            keep.insert(base.as_os_str().to_string_lossy().into_owned());
        }
        keep.extend(
            installed
                .iter()
                .filter(|v| v.starts_with(&format!("{name}.")) || v.starts_with(&format!("{name}-")))
                .cloned(),
        );
        if keep.len() == before && !keep.contains(name) {
            tracing::warn!(version = %name, "pyenv version is not installed; not offering any pyenv version");
            return None;
        }
    }
    Some(keep)
}

/// Names of the pyenv-virtualenv environments stored inside an installed version.
fn pyenv_envs(version: &Path) -> Vec<String> {
    children(&version.join("envs")).iter().map(|p| file_name(p)).collect()
}

fn pyenv(ctx: &ScanContext<'_>) -> Vec<Finding> {
    let root = ctx.home.join(".pyenv");
    let versions_dir = root.join("versions");
    let versions = version_dirs(&versions_dir);
    if versions.is_empty() {
        return Vec::new();
    }
    let installed: Vec<String> = versions.iter().map(|(n, _)| n.clone()).collect();
    let selected = pyenv_selected(&std::fs::read_to_string(root.join("version")).unwrap_or_default());
    let Some(keep) = pyenv_keep(&versions_dir, &installed, &selected) else {
        return Vec::new();
    };
    versions
        .iter()
        .filter(|(name, _)| !keep.contains(name))
        .filter_map(|(name, path)| {
            let mut detail = "Python installed with pyenv that is not your global version. Projects may still select \
                              it with a .python-version file; reinstall with `pyenv install`."
                .to_owned();
            let envs = pyenv_envs(path);
            if !envs.is_empty() {
                let _ = write!(
                    detail,
                    " It also contains {} virtualenv(s) that are deleted with it: {}.",
                    envs.len(),
                    envs.join(", ")
                );
            }
            finding(
                ctx,
                format!("toolchains:pyenv:{name}"),
                format!("Python {name} (pyenv)"),
                path,
                CleanupAction::RemovePath { path: path.clone(), root: versions_dir.clone() },
                &detail,
            )
        })
        .collect()
}

// ---- JetBrains -----------------------------------------------------------------------------

/// Splits `IntelliJIdea2024.3` into (`IntelliJIdea`, [2024, 3]); `None` for unversioned folders.
fn jetbrains_version(name: &str) -> Option<(String, Vec<u64>)> {
    let start = name.find(|c: char| c.is_ascii_digit())?;
    let (product, version) = name.split_at(start);
    let year: u64 = version.split('.').next()?.parse().ok()?;
    if product.is_empty() || !(2000..=2100).contains(&year) || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return None;
    }
    Some((product.to_owned(), version_key(version)))
}

fn jetbrains(ctx: &ScanContext<'_>) -> Vec<Finding> {
    let base = match ctx.os {
        Os::MacOs => ctx.home.join("Library/Application Support/JetBrains"),
        Os::Linux => ctx.home.join(".config/JetBrains"),
    };
    let mut products: BTreeMap<String, Vec<(Vec<u64>, PathBuf)>> = BTreeMap::new();
    for (name, path) in version_dirs(&base) {
        if let Some((product, version)) = jetbrains_version(&name) {
            products.entry(product).or_default().push((version, path));
        }
    }
    products
        .into_values()
        .flat_map(|mut versions| {
            versions.sort();
            versions.pop(); // keep the newest version of each IDE
            versions
        })
        // Scratch files are the user's own writing; never offer a folder that still holds some.
        .filter(|(_, path)| children(&path.join("scratches")).is_empty())
        .filter_map(|(_, path)| {
            let name = file_name(&path);
            finding(
                ctx,
                format!("toolchains:jetbrains:{name}"),
                format!("{name} settings"),
                &path,
                CleanupAction::RemovePath { path: path.clone(), root: base.clone() },
                "Settings and plugins of an older JetBrains IDE version. Newer versions import them on \
                 upgrade. Folders that still contain scratch files are never offered.",
            )
        })
        .collect()
}

// ---- Android -------------------------------------------------------------------------------

fn android_images(ctx: &ScanContext<'_>) -> Vec<Finding> {
    let sdk = match ctx.os {
        Os::MacOs => ctx.home.join("Library/Android/sdk"),
        Os::Linux => ctx.home.join("Android/Sdk"),
    };
    let images = sdk.join("system-images");
    // Layout: system-images/<api>/<tag>/<abi>/
    let abis: Vec<PathBuf> = children(&images)
        .into_iter()
        .filter(|p| is_real_dir(p))
        .flat_map(|api| children(&api).into_iter().filter(|p| is_real_dir(p)))
        .flat_map(|tag| children(&tag).into_iter().filter(|p| is_real_dir(p)))
        .collect();
    abis.iter()
        .filter_map(|abi| {
            let rel = abi.strip_prefix(&images).ok()?.display().to_string();
            finding(
                ctx,
                format!("toolchains:android:{rel}"),
                format!("Android image {}", rel.replace('/', " · ")),
                abi,
                CleanupAction::RemovePath { path: abi.clone(), root: images.clone() },
                "Android emulator system image. Emulators (AVDs) built on it stop working until it is \
                 reinstalled with the SDK Manager.",
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::model::Risk;
    use crate::scanners::testutil::{BIG, Env};

    fn titles(found: &[Finding]) -> Vec<&str> {
        let mut t: Vec<&str> = found.iter().map(|f| f.title.as_str()).collect();
        t.sort_unstable();
        t
    }

    /// Captured from rustup 1.29 on macOS.
    const RUSTUP_LIST: &str = "stable-aarch64-apple-darwin (default)\nnightly-aarch64-apple-darwin\n\
        1.94.0-aarch64-apple-darwin\n1.95.0-aarch64-apple-darwin\n1.100-aarch64-apple-darwin (active)\n";

    #[test]
    fn rustup_keeps_default_and_active() {
        assert_eq!(
            removable_rustup_toolchains(RUSTUP_LIST),
            ["nightly-aarch64-apple-darwin", "1.94.0-aarch64-apple-darwin", "1.95.0-aarch64-apple-darwin"]
        );
        assert!(removable_rustup_toolchains("stable-x86_64-unknown-linux-gnu (active, default)\n").is_empty());
        assert!(
            removable_rustup_toolchains("1.70.0-x86_64-unknown-linux-gnu (override)\n").is_empty(),
            "older rustup marks a directory override this way"
        );
    }

    #[test]
    fn rustup_toolchains_are_uninstalled_with_rustup() {
        let env = Env::new();
        env.file(".rustup/toolchains/1.94.0-aarch64-apple-darwin/lib/librustc.dylib", BIG);
        env.file(".rustup/toolchains/stable-aarch64-apple-darwin/lib/librustc.dylib", BIG);
        let runner = FakeRunner::new().respond("rustup toolchain list", true, RUSTUP_LIST);
        let found = ToolchainsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(titles(&found), ["Rust 1.94.0-aarch64-apple-darwin"]);
        assert_eq!(found[0].risk, Risk::Review);
        assert_eq!(found[0].category, Category::Toolchains);
        assert_eq!(
            found[0].action,
            Some(CleanupAction::Run(KnownCommand::RustupUninstall { toolchain: "1.94.0-aarch64-apple-darwin".into() }))
        );
        assert!(found[0].last_modified.is_some());
        let failing = FakeRunner::new().respond("rustup toolchain list", false, "");
        assert!(ToolchainsScanner.scan(&env.ctx(Os::MacOs, &failing)).expect("scan").is_empty());
    }

    #[test]
    fn rustup_failure_does_not_hide_other_toolchains() {
        let env = Env::new();
        env.file(".rustup/toolchains/1.94.0-aarch64-apple-darwin/lib/librustc.dylib", BIG);
        env.file(".pyenv/versions/3.11.9/bin/python", BIG);
        env.file(".pyenv/versions/3.12.4/bin/python", BIG);
        std::fs::write(env.home.join(".pyenv/version"), "3.12.4\n").expect("version");
        let runner = FakeRunner::new().time_out("rustup toolchain list");
        let found = ToolchainsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan never fails");
        assert_eq!(titles(&found), ["Python 3.11.9 (pyenv)"]);
    }

    #[test]
    fn nvm_keeps_the_resolved_default() {
        let env = Env::new();
        for v in ["v18.20.4", "v20.11.1", "v20.9.0", "v22.3.0"] {
            env.file(&format!(".nvm/versions/node/{v}/bin/node"), BIG);
        }
        let runner = FakeRunner::new();
        env.file(".nvm/alias/default", 0);
        std::fs::write(env.home.join(".nvm/alias/default"), "20\n").expect("alias");
        let found = ToolchainsScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(titles(&found), ["Node v18.20.4 (nvm)", "Node v20.9.0 (nvm)", "Node v22.3.0 (nvm)"]);
        assert!(
            matches!(&found[0].action, Some(CleanupAction::RemovePath { root, .. }) if root.ends_with("versions/node"))
        );
        // lts/* resolves through alias/lts/*.
        std::fs::write(env.home.join(".nvm/alias/default"), "lts/*").expect("alias");
        env.file(".nvm/alias/lts/*", 0);
        std::fs::write(env.home.join(".nvm/alias/lts/*"), "lts/iron").expect("alias");
        env.file(".nvm/alias/lts/iron", 0);
        std::fs::write(env.home.join(".nvm/alias/lts/iron"), "v18.20.4").expect("alias");
        let found = ToolchainsScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert!(!titles(&found).contains(&"Node v18.20.4 (nvm)"));
        // No default alias: the newest version is kept.
        std::fs::remove_file(env.home.join(".nvm/alias/default")).expect("rm");
        let found = ToolchainsScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert!(!titles(&found).contains(&"Node v22.3.0 (nvm)"));
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn fnm_keeps_aliased_versions() {
        let env = Env::new();
        for v in ["v20.11.1", "v22.3.0"] {
            env.file(&format!(".local/share/fnm/node-versions/{v}/installation/bin/node"), BIG);
        }
        let runner = FakeRunner::new();
        // Without aliases the newest is kept.
        let found = ToolchainsScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(titles(&found), ["Node v20.11.1 (fnm)"]);
        std::fs::create_dir_all(env.home.join(".local/share/fnm/aliases")).expect("mkdir");
        std::os::unix::fs::symlink(
            env.home.join(".local/share/fnm/node-versions/v20.11.1/installation"),
            env.home.join(".local/share/fnm/aliases/default"),
        )
        .expect("symlink");
        let found = ToolchainsScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(titles(&found), ["Node v22.3.0 (fnm)"]);
    }

    #[test]
    fn pyenv_keeps_global_versions() {
        let env = Env::new();
        for v in ["3.11.9", "3.12.4", "3.13.0"] {
            env.file(&format!(".pyenv/versions/{v}/bin/python"), BIG);
        }
        env.file(".pyenv/version", 0);
        std::fs::write(env.home.join(".pyenv/version"), "3.12.4\n3.13.0\n").expect("version");
        let runner = FakeRunner::new();
        let found = ToolchainsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(titles(&found), ["Python 3.11.9 (pyenv)"]);
    }

    fn pyenv_versions(env: &Env, versions: &[&str], version_file: &str) -> Vec<Finding> {
        for v in versions {
            env.file(&format!(".pyenv/versions/{v}/bin/python"), BIG);
        }
        std::fs::write(env.home.join(".pyenv/version"), version_file).expect("version");
        let runner = FakeRunner::new();
        ToolchainsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan")
    }

    #[test]
    fn pyenv_global_virtualenv_keeps_its_base_version() {
        let env = Env::new();
        env.file(".pyenv/versions/3.11.9/envs/work/bin/python", BIG);
        std::os::unix::fs::symlink(
            env.home.join(".pyenv/versions/3.11.9/envs/work"),
            env.home.join(".pyenv/versions/work"),
        )
        .expect("symlink");
        let found = pyenv_versions(&env, &["3.11.9", "3.12.4"], "work\n");
        assert_eq!(titles(&found), ["Python 3.12.4 (pyenv)"], "3.11.9 hosts the global virtualenv");
    }

    #[test]
    fn pyenv_version_file_comments_and_prefixes() {
        let env = Env::new();
        let found = pyenv_versions(&env, &["3.11.9", "3.12.4"], "3.12.4 # main interpreter\n");
        assert_eq!(titles(&found), ["Python 3.11.9 (pyenv)"]);
        let env = Env::new();
        let found = pyenv_versions(&env, &["3.11.9", "3.12.1", "3.12.4"], "3.12\n");
        assert_eq!(titles(&found), ["Python 3.11.9 (pyenv)"], "every 3.12.x is kept for prefix 3.12");
        let env = Env::new();
        let found = pyenv_versions(&env, &["3.11.9", "3.12.4"], "system\n# only comments\n");
        assert_eq!(titles(&found).len(), 2, "system Python selects no pyenv version");
    }

    #[test]
    fn pyenv_offers_nothing_when_global_cannot_be_resolved() {
        let env = Env::new();
        let found = pyenv_versions(&env, &["3.11.9", "3.12.4"], "3.10.2\n");
        assert!(found.is_empty());
    }

    #[test]
    fn pyenv_warns_about_virtualenvs_inside_a_version() {
        let env = Env::new();
        env.file(".pyenv/versions/3.11.9/envs/old-project/bin/python", BIG);
        let found = pyenv_versions(&env, &["3.11.9", "3.12.4"], "3.12.4\n");
        assert_eq!(titles(&found), ["Python 3.11.9 (pyenv)"]);
        assert!(
            found[0].detail.contains("1 virtualenv(s) that are deleted with it: old-project"),
            "{}",
            found[0].detail
        );
    }

    #[test]
    fn jetbrains_keeps_newest_per_product() {
        assert_eq!(jetbrains_version("IntelliJIdea2024.3"), Some(("IntelliJIdea".into(), vec![2024, 3])));
        assert_eq!(jetbrains_version("PyCharm2025.1.2"), Some(("PyCharm".into(), vec![2025, 1, 2])));
        assert_eq!(jetbrains_version("consentOptions"), None);
        assert_eq!(jetbrains_version("Toolbox"), None);
        assert_eq!(jetbrains_version("Foo1.2"), None);
        let env = Env::new();
        for d in ["GoLand2024.3", "GoLand2025.2", "GoLand2023.1", "PyCharm2025.1", "consentOptions"] {
            env.file(&format!("Library/Application Support/JetBrains/{d}/options/x.xml"), BIG);
        }
        let runner = FakeRunner::new();
        let found = ToolchainsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(titles(&found), ["GoLand2023.1 settings", "GoLand2024.3 settings"]);
    }

    #[test]
    fn jetbrains_folders_with_scratch_files_are_never_offered() {
        let env = Env::new();
        for d in ["GoLand2023.1", "GoLand2024.3", "GoLand2025.2"] {
            env.file(&format!("Library/Application Support/JetBrains/{d}/options/x.xml"), BIG);
        }
        env.file("Library/Application Support/JetBrains/GoLand2023.1/scratches/notes.sql", 100);
        std::fs::create_dir_all(env.home.join("Library/Application Support/JetBrains/GoLand2024.3/scratches"))
            .expect("empty scratches dir");
        let runner = FakeRunner::new();
        let found = ToolchainsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(titles(&found), ["GoLand2024.3 settings"], "an empty scratches folder does not block");
    }

    #[test]
    fn android_system_images_listed_per_abi() {
        let env = Env::new();
        env.file("Android/Sdk/system-images/android-34/google_apis/x86_64/system.img", BIG);
        env.file("Android/Sdk/system-images/android-30/default/x86_64/system.img", BIG);
        let runner = FakeRunner::new();
        let found = ToolchainsScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        assert_eq!(
            titles(&found),
            ["Android image android-30 · default · x86_64", "Android image android-34 · google_apis · x86_64"]
        );
        assert!(found.iter().all(|f| f.risk == Risk::Review));
        assert_eq!(ToolchainsScanner.id(), "toolchains");
        assert!(ToolchainsScanner.supports(Os::MacOs) && !ToolchainsScanner.name().is_empty());
    }
}
