//! Rules the user adds in `settings.json` for folders no built-in rule knows.
//!
//! Custom rules are confined to the home folder (never system paths, never admin) and go through
//! the same [`SafetyPolicy`] as built-in rules, at scan time and again before removal. A rule
//! naming a protected folder (`~/Documents` itself, `~/.ssh`, …) yields nothing in either mode.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    MIN_BYTES, ScanContext, ScanError, Scanner, base_finding, children, file_name, is_real_dir, with_shared_note,
};
use crate::model::{Category, CleanupAction, Finding, Os, Risk, SPECIFIC};
use crate::safety::SafetyPolicy;

/// Whether a custom rule reports its folder as one item or each child separately.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomMode {
    #[default]
    Whole,
    Children,
}

/// Risk label for a custom rule; `review` unless the user writes `safe`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomRisk {
    Safe,
    #[default]
    Review,
}

/// One user rule, e.g. `{ "path": "~/Projects/old-renders", "mode": "children" }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRule {
    /// `~/…` or an absolute path inside the home folder.
    pub path: String,
    #[serde(default)]
    pub mode: CustomMode,
    /// Shown instead of the folder name (whole mode) or as the detail prefix (children mode).
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub risk: CustomRisk,
}

impl CustomRule {
    /// The rule's folder, or why it is rejected: it must be `~/…` or absolute, have no `..`, and
    /// lie strictly inside `home`.
    pub fn resolve(&self, home: &Path) -> Result<PathBuf, String> {
        let path = if let Some(rest) = self.path.strip_prefix("~/") {
            home.join(rest)
        } else if Path::new(&self.path).is_absolute() {
            PathBuf::from(&self.path)
        } else {
            return Err(format!("`{}`: use ~/… or an absolute path", self.path));
        };
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(format!("`{}`: `..` is not allowed", self.path));
        }
        if path == home || !path.starts_with(home) {
            return Err(format!("`{}`: custom rules must point inside your home folder", self.path));
        }
        Ok(path)
    }
}

/// Scanner for the user's custom rules.
#[derive(Debug, Clone, Default)]
pub struct CustomRulesScanner {
    pub rules: Vec<CustomRule>,
}

impl CustomRulesScanner {
    fn finding(ctx: &ScanContext<'_>, rule: &CustomRule, path: &Path, root: &Path, title: String) -> Option<Finding> {
        let report = ctx.measure(path)?;
        if report.bytes < MIN_BYTES {
            return None;
        }
        let detail = format!("From your custom rule for {}.", rule.path);
        Some(Finding {
            detail: with_shared_note(detail, &report),
            path: Some(path.to_path_buf()),
            bytes: Some(report.bytes),
            last_modified: report.newest,
            risk: match rule.risk {
                CustomRisk::Safe => Risk::Safe,
                CustomRisk::Review => Risk::Review,
            },
            action: Some(CleanupAction::RemovePath { path: path.to_path_buf(), root: root.to_path_buf() }),
            specificity: SPECIFIC,
            ..base_finding("custom", format!("custom:{}", path.display()), Category::Custom, title)
        })
    }
}

impl Scanner for CustomRulesScanner {
    fn id(&self) -> &'static str {
        "custom"
    }

    fn name(&self) -> &'static str {
        "Your rules"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let policy = SafetyPolicy::for_home(&ctx.home);
        let mut found = Vec::new();
        let mut problems = Vec::new();
        for rule in &self.rules {
            let target = match rule.resolve(&ctx.home) {
                Ok(t) => t,
                Err(e) => {
                    problems.push(e);
                    continue;
                }
            };
            if !is_real_dir(&target) {
                continue;
            }
            // A protected folder is refused in both modes: a typo must never list ~/.ssh keys or
            // the whole of ~/Documents as deletable items.
            if policy.is_protected(&target) || target.canonicalize().is_ok_and(|c| policy.is_protected(&c)) {
                problems.push(format!("`{}` is a protected folder", rule.path));
                continue;
            }
            match rule.mode {
                CustomMode::Whole => {
                    let Some(root) = target.parent() else { continue };
                    if let Err(e) = policy.validate(&target, root) {
                        problems.push(format!("`{}`: {e}", rule.path));
                        continue;
                    }
                    let title = rule.title.clone().unwrap_or_else(|| file_name(&target));
                    found.extend(Self::finding(ctx, rule, &target, root, title));
                }
                CustomMode::Children => {
                    for child in children(&target) {
                        if policy.validate(&child, &target).is_ok() {
                            let title = match &rule.title {
                                Some(t) => format!("{t} · {}", file_name(&child)),
                                None => file_name(&child),
                            };
                            found.extend(Self::finding(ctx, rule, &child, &target, title));
                        }
                    }
                }
            }
        }
        // Skipped rules are shown (not only logged) so a rule that does nothing explains why.
        found.extend(problems.into_iter().map(|problem| {
            tracing::warn!(problem = %problem, "custom rule skipped");
            Finding {
                detail: format!("{problem}. Fix the rule in settings.json."),
                ..base_finding(
                    "custom",
                    format!("custom:skipped:{problem}"),
                    Category::Custom,
                    "Rule skipped".to_owned(),
                )
            }
        }));
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};

    fn rule(json: &str) -> CustomRule {
        serde_json::from_str(json).expect("rule")
    }

    fn scan(env: &Env, rules: Vec<CustomRule>) -> Result<Vec<Finding>, ScanError> {
        let runner = FakeRunner::new();
        CustomRulesScanner { rules }.scan(&env.ctx(Os::MacOs, &runner))
    }

    #[test]
    fn rule_json_and_defaults() {
        let r = rule(r#"{"path":"~/x"}"#);
        assert_eq!((r.mode, r.risk, r.title), (CustomMode::Whole, CustomRisk::Review, None));
        let r = rule(r#"{"path":"~/x","mode":"children","risk":"safe","title":"X"}"#);
        assert_eq!((r.mode, r.risk), (CustomMode::Children, CustomRisk::Safe));
        assert!(serde_json::from_str::<CustomRule>(r#"{"path":"~/x","rm":"-rf"}"#).is_err(), "unknown fields");
        assert!(serde_json::from_str::<CustomRule>(r#"{"path":"~/x","mode":"all"}"#).is_err());
    }

    #[test]
    fn paths_must_stay_inside_home() {
        let home = Path::new("/Users/u");
        assert_eq!(rule(r#"{"path":"~/a/b"}"#).resolve(home), Ok(PathBuf::from("/Users/u/a/b")));
        assert_eq!(rule(r#"{"path":"/Users/u/a"}"#).resolve(home), Ok(PathBuf::from("/Users/u/a")));
        for bad in ["relative/x", "/etc", "/Users/other/x", "~/../other", "~/a/../../x", "/Users/u"] {
            let json = format!(r#"{{"path":"{bad}"}}"#);
            assert!(rule(&json).resolve(home).is_err(), "{bad}");
        }
    }

    #[test]
    fn whole_and_children_rules() {
        let env = Env::new();
        env.file("renders/2023/a.mov", BIG);
        env.file("renders/2024/b.mov", BIG);
        env.file("old-build/out.bin", BIG);
        let found = scan(
            &env,
            vec![
                rule(r#"{"path":"~/renders","mode":"children","title":"Renders","risk":"safe"}"#),
                rule(r#"{"path":"~/old-build"}"#),
                rule(r#"{"path":"~/missing"}"#),
            ],
        )
        .expect("scan");
        let mut titles: Vec<_> = found.iter().map(|f| (f.title.as_str(), f.risk)).collect();
        titles.sort_unstable_by_key(|t| t.0);
        assert_eq!(
            titles,
            [("Renders · 2023", Risk::Safe), ("Renders · 2024", Risk::Safe), ("old-build", Risk::Review)]
        );
        assert!(found.iter().all(|f| f.category == Category::Custom));
        let build = found.iter().find(|f| f.title == "old-build").expect("build");
        assert_eq!(
            build.action,
            Some(CleanupAction::RemovePath { path: env.home.join("old-build"), root: env.home.clone() })
        );
    }

    #[test]
    fn protected_and_invalid_rules_yield_nothing() {
        let env = Env::new();
        env.file("Documents/thesis.pdf", BIG);
        env.file(".ssh/id_ed25519", BIG);
        let skipped = |found: Vec<Finding>| -> Vec<String> {
            assert!(found.iter().all(|f| !f.is_actionable() && f.title == "Rule skipped"), "{found:#?}");
            found.into_iter().map(|f| f.detail).collect()
        };
        let details =
            skipped(scan(&env, vec![rule(r#"{"path":"~/Documents"}"#), rule(r#"{"path":"/etc"}"#)]).expect("scan"));
        assert!(details[0].contains("protected folder") && details[1].contains("inside your home"), "{details:?}");
        let details = skipped(scan(&env, vec![rule(r#"{"path":"~/.ssh","mode":"children"}"#)]).expect("scan"));
        assert!(details[0].contains("protected folder"), "never list the keys in ~/.ssh");
        env.file("Documents/old-stuff/big.iso", BIG);
        let ok = scan(&env, vec![rule(r#"{"path":"~/Documents/old-stuff"}"#)]).expect("scan");
        assert_eq!(ok.len(), 1, "a folder inside a protected one is fine");
        assert!(scan(&env, Vec::new()).expect("no rules").is_empty());
        let s = CustomRulesScanner::default();
        assert_eq!((s.id(), s.name()), ("custom", "Your rules"));
        assert!(s.supports(Os::Linux));
    }
}
