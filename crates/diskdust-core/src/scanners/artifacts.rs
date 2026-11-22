//! Rebuildable build output (`target/`, `node_modules/`, …) under the user's project folders.

use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::{
    MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir, with_shared_note,
};
use crate::model::{Category, CleanupAction, Finding, Os, Risk, SPECIFIC};

/// Maximum folder depth below a project root.
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Cargo,
    NodeModules,
    NextJs,
    Terraform,
    PythonVenv,
    GradleBuild,
    GradleProjectCache,
}

impl Kind {
    const fn label(self) -> &'static str {
        match self {
            Self::Cargo => "Rust target/",
            Self::NodeModules => "node_modules/",
            Self::NextJs => "Next.js .next/",
            Self::Terraform => "Terraform .terraform/",
            Self::PythonVenv => "Python virtualenv",
            Self::GradleBuild => "Gradle build/",
            Self::GradleProjectCache => "Gradle .gradle/",
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::Cargo => "Cargo build output. Rebuilt by `cargo build`.",
            Self::NodeModules => "Installed npm packages. Restored by `npm install` / `pnpm install`.",
            Self::NextJs => "Next.js build cache. Rebuilt by `next build` / `next dev`.",
            Self::Terraform => "Downloaded providers and modules. Restored by `terraform init`.",
            Self::PythonVenv => "Python virtual environment. Recreate it and reinstall dependencies.",
            Self::GradleBuild => "Gradle build output. Rebuilt by the next build.",
            Self::GradleProjectCache => "Gradle project cache. Rebuilt by the next build.",
        }
    }

    const fn risk(self) -> Risk {
        match self {
            Self::PythonVenv => Risk::Review,
            _ => Risk::Safe,
        }
    }
}

fn any_exists(dir: &Path, names: &[&str]) -> bool {
    names.iter().any(|n| dir.join(n).is_file())
}

fn classify(dir: &Path, name: &str, parent: &Path) -> Option<Kind> {
    match name {
        "target" if any_exists(parent, &["Cargo.toml"]) || dir.join("CACHEDIR.TAG").is_file() => Some(Kind::Cargo),
        "node_modules" if any_exists(parent, &["package.json"]) => Some(Kind::NodeModules),
        ".next" if any_exists(parent, &["package.json"]) => Some(Kind::NextJs),
        ".terraform" if children(parent).iter().any(|p| p.extension().is_some_and(|e| e == "tf")) => {
            Some(Kind::Terraform)
        }
        ".venv" | "venv" if dir.join("pyvenv.cfg").is_file() => Some(Kind::PythonVenv),
        "build" if any_exists(parent, &["build.gradle", "build.gradle.kts"]) => Some(Kind::GradleBuild),
        ".gradle"
            if any_exists(parent, &["settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"]) =>
        {
            Some(Kind::GradleProjectCache)
        }
        _ => None,
    }
}

/// Walks `root` and returns artifact folders (does not descend into matches).
fn discover(root: &Path, ctx: &ScanContext<'_>) -> Vec<(PathBuf, Kind)> {
    let mut found = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if ctx.is_cancelled() {
            break;
        }
        for child in children(&dir) {
            if !is_real_dir(&child) {
                continue;
            }
            let name = file_name(&child);
            if let Some(kind) = classify(&child, &name, &dir) {
                found.push((child, kind));
            } else if !name.starts_with('.') && name != "Library" && depth < MAX_DEPTH {
                stack.push((child, depth + 1));
            }
        }
    }
    found
}

#[derive(Debug)]
pub struct BuildArtifactsScanner;

impl Scanner for BuildArtifactsScanner {
    fn id(&self) -> &'static str {
        "artifacts"
    }

    fn name(&self) -> &'static str {
        "Build artifacts in project folders"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let candidates: Vec<(PathBuf, PathBuf, Kind)> = ctx
            .project_roots
            .iter()
            .filter(|root| is_real_dir(root))
            .flat_map(|root| discover(root, ctx).into_iter().map(move |(p, k)| (root.clone(), p, k)))
            .collect();
        Ok(candidates
            .par_iter()
            .filter_map(|(root, path, kind)| {
                let report = ctx.measure(path)?;
                if report.bytes < MIN_BYTES {
                    return None;
                }
                let project = path.parent().map_or_default(file_name);
                Some(Finding {
                    detail: with_shared_note(kind.detail().to_owned(), &report),
                    path: Some(path.clone()),
                    bytes: Some(report.bytes),
                    last_modified: report.newest,
                    risk: kind.risk(),
                    action: Some(CleanupAction::RemovePath { path: path.clone(), root: root.clone() }),
                    specificity: SPECIFIC,
                    ..base_finding(
                        "artifacts",
                        format!("artifacts:{}", path.display()),
                        Category::BuildArtifacts,
                        format!("{project} · {}", kind.label()),
                    )
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};

    fn scan(env: &Env) -> Vec<Finding> {
        let runner = FakeRunner::new();
        let mut found = BuildArtifactsScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        found.sort_by(|a, b| a.title.cmp(&b.title));
        found
    }

    #[test]
    fn finds_each_artifact_kind() {
        let env = Env::new();
        env.file("code/rusty/Cargo.toml", 1);
        env.file("code/rusty/target/debug/big", BIG);
        env.file("code/web/package.json", 1);
        env.file("code/web/node_modules/react/index.js", BIG);
        env.file("code/web/.next/cache/x", BIG);
        env.file("code/infra/main.tf", 1);
        env.file("code/infra/.terraform/providers/aws", BIG);
        env.file("code/py/.venv/pyvenv.cfg", 1);
        env.file("code/py/.venv/lib/site.py", BIG);
        env.file("code/jvm/build.gradle.kts", 1);
        env.file("code/jvm/build/classes/A.class", BIG);
        env.file("code/jvm/.gradle/8.0/cache", BIG);
        let found = scan(&env);
        let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "infra · Terraform .terraform/",
                "jvm · Gradle .gradle/",
                "jvm · Gradle build/",
                "py · Python virtualenv",
                "rusty · Rust target/",
                "web · Next.js .next/",
                "web · node_modules/",
            ]
        );
        let venv = found.iter().find(|f| f.title.contains("virtualenv")).expect("venv");
        assert_eq!(venv.risk, Risk::Review);
        assert!(
            matches!(&found[0].action, Some(CleanupAction::RemovePath { root, .. }) if *root == env.home.join("code"))
        );
    }

    #[test]
    fn ignores_lookalikes_and_nested_matches() {
        let env = Env::new();
        env.file("code/notes/target/data", BIG);
        env.file("code/notes/build/out", BIG);
        env.file("code/web/package.json", 1);
        env.file("code/web/node_modules/pkg/package.json", 1);
        env.file("code/web/node_modules/pkg/node_modules/dep/x", BIG);
        env.file("code/.hidden/proj/Cargo.toml", 1);
        env.file("code/.hidden/proj/target/x", BIG);
        let found = scan(&env);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].path.as_deref(), Some(env.home.join("code/web/node_modules").as_path()));
    }

    #[test]
    fn pnpm_linked_node_modules_report_only_their_own_bytes() {
        let env = Env::new();
        env.file("code/web/package.json", 1);
        env.file("code/web/node_modules/own/big", BIG);
        let store = env.file("Library/pnpm/store/v10/files/aa/blob", BIG * 2);
        std::fs::hard_link(&store, env.home.join("code/web/node_modules/own/linked")).expect("link");
        let found = scan(&env);
        assert_eq!(found.len(), 1);
        let bytes = found[0].bytes.expect("bytes");
        assert!(bytes >= BIG as u64 && bytes < (BIG * 2) as u64, "{bytes}");
        assert!(found[0].detail.contains("hard-linked from elsewhere"), "{}", found[0].detail);
    }

    #[test]
    fn cargo_target_detected_by_cachedir_tag() {
        let env = Env::new();
        env.file("code/ws/crates/a/target/CACHEDIR.TAG", 1);
        env.file("code/ws/crates/a/target/debug/x", BIG);
        assert_eq!(scan(&env).len(), 1);
    }

    #[test]
    fn respects_depth_limit_and_missing_roots() {
        let env = Env::new();
        let deep = "code/a/b/c/d/e/f/g/h/i/proj";
        env.file(&format!("{deep}/Cargo.toml"), 1);
        env.file(&format!("{deep}/target/x"), BIG);
        assert!(scan(&env).is_empty());
        let runner = FakeRunner::new();
        let mut ctx = env.ctx(Os::Linux, &runner);
        ctx.project_roots = vec![env.home.join("nope")];
        assert!(BuildArtifactsScanner.scan(&ctx).expect("scan").is_empty());
        assert!(BuildArtifactsScanner.supports(Os::Linux));
        assert_eq!(BuildArtifactsScanner.id(), "artifacts");
        assert!(!BuildArtifactsScanner.name().is_empty());
    }
}
