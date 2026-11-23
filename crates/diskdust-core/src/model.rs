//! Core domain types shared by scanners, the cleanup executor and the UI.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Operating system family the engine is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Os {
    MacOs,
    Linux,
}

impl Os {
    /// Returns the OS this binary was compiled for, or `None` on unsupported platforms.
    pub const fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

/// Grouping shown in the UI sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Category {
    Containers,
    DeveloperCaches,
    BuildArtifacts,
    AppCaches,
    Logs,
    Xcode,
    Backups,
    OrphanedAppData,
    Trash,
    System,
    Toolchains,
    Installers,
    LargeFiles,
}

impl Category {
    pub const ALL: [Self; 13] = [
        Self::Containers,
        Self::DeveloperCaches,
        Self::Toolchains,
        Self::BuildArtifacts,
        Self::Installers,
        Self::LargeFiles,
        Self::AppCaches,
        Self::Logs,
        Self::Xcode,
        Self::Backups,
        Self::OrphanedAppData,
        Self::Trash,
        Self::System,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Containers => "Containers",
            Self::DeveloperCaches => "Developer caches",
            Self::BuildArtifacts => "Build artifacts",
            Self::AppCaches => "App caches",
            Self::Logs => "Logs",
            Self::Xcode => "Xcode",
            Self::Backups => "Device backups",
            Self::OrphanedAppData => "Orphaned app data",
            Self::Trash => "Trash",
            Self::System => "System",
            Self::Toolchains => "Old toolchains",
            Self::Installers => "Installers",
            Self::LargeFiles => "Large files",
        }
    }
}

impl Category {
    /// Command-line name: the label in lowercase with dashes (`developer-caches`).
    pub fn slug(self) -> String {
        self.label().to_ascii_lowercase().replace(' ', "-")
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.slug() == slug)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How safe an item is to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Risk {
    /// Rebuildable cache or derived data; safe to remove.
    Safe,
    /// May contain user data or expensive-to-recreate state; review before removing.
    Review,
}

/// Privilege required to clean an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Privilege {
    User,
    Admin,
}

/// Commands the engine is allowed to run. This is a closed set: there is no way to express an
/// arbitrary command, which keeps the privileged helper's attack surface fixed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KnownCommand {
    DockerPruneImages,
    DockerPruneContainers,
    DockerPruneVolumes,
    DockerPruneBuildCache,
    BrewCleanup,
    GoCleanModCache,
    GoCleanBuildCache,
    SimctlDeleteUnavailable,
    FinderEmptyTrash,
    TimeMachineDeleteLocalSnapshots,
    JournalVacuum,
    AptClean,
    DnfClean,
    PacmanClean,
    SnapRemoveRevision {
        name: String,
        revision: String,
    },
    RustupUninstall {
        toolchain: String,
    },
    /// `docker image rm <id>`; `id` is `sha256:` followed by 64 lowercase hex digits.
    DockerRemoveImage {
        id: String,
    },
    /// `docker volume rm <name>`.
    DockerRemoveVolume {
        name: String,
    },
}

impl KnownCommand {
    /// Fixed argv for this command. Element 0 is the program.
    pub fn argv(&self) -> Vec<String> {
        let fixed: &[&str] = match self {
            Self::DockerPruneImages => &["docker", "image", "prune", "--all", "--force"],
            Self::DockerPruneContainers => &["docker", "container", "prune", "--force"],
            Self::DockerPruneVolumes => &["docker", "volume", "prune", "--all", "--force"],
            Self::DockerPruneBuildCache => &["docker", "builder", "prune", "--all", "--force"],
            Self::BrewCleanup => &["brew", "cleanup", "--prune=all"],
            Self::GoCleanModCache => &["go", "clean", "-modcache"],
            Self::GoCleanBuildCache => &["go", "clean", "-cache"],
            Self::SimctlDeleteUnavailable => &["xcrun", "simctl", "delete", "unavailable"],
            Self::FinderEmptyTrash => &["osascript", "-e", "tell application \"Finder\" to empty trash"],
            Self::TimeMachineDeleteLocalSnapshots => &["tmutil", "deletelocalsnapshots", "/"],
            Self::JournalVacuum => &["journalctl", "--vacuum-time=7d"],
            Self::AptClean => &["apt-get", "clean"],
            Self::DnfClean => &["dnf", "clean", "all"],
            Self::PacmanClean => &["pacman", "-Sc", "--noconfirm"],
            Self::SnapRemoveRevision { name, revision } => {
                return vec!["snap".to_owned(), "remove".to_owned(), name.clone(), format!("--revision={revision}")];
            }
            Self::RustupUninstall { toolchain } => {
                return vec!["rustup".to_owned(), "toolchain".to_owned(), "uninstall".to_owned(), toolchain.clone()];
            }
            Self::DockerRemoveImage { id } => {
                return vec!["docker".to_owned(), "image".to_owned(), "rm".to_owned(), id.clone()];
            }
            Self::DockerRemoveVolume { name } => {
                return vec!["docker".to_owned(), "volume".to_owned(), "rm".to_owned(), name.clone()];
            }
        };
        fixed.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Whether this command needs to run with administrator privileges.
    pub const fn requires_admin(&self) -> bool {
        matches!(
            self,
            Self::TimeMachineDeleteLocalSnapshots
                | Self::JournalVacuum
                | Self::AptClean
                | Self::DnfClean
                | Self::PacmanClean
                | Self::SnapRemoveRevision { .. }
        )
    }

    /// Whether this is a Docker prune, whose output reports the space actually reclaimed.
    pub const fn is_docker_prune(&self) -> bool {
        matches!(
            self,
            Self::DockerPruneImages
                | Self::DockerPruneContainers
                | Self::DockerPruneVolumes
                | Self::DockerPruneBuildCache
        )
    }

    /// Validates command arguments that originate from scanned data.
    pub fn is_well_formed(&self) -> bool {
        match self {
            Self::SnapRemoveRevision { name, revision } => {
                is_snap_name(name) && !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit())
            }
            Self::RustupUninstall { toolchain } => is_toolchain_name(toolchain),
            Self::DockerRemoveImage { id } => is_docker_image_id(id),
            Self::DockerRemoveVolume { name } => is_docker_volume_name(name),
            _ => true,
        }
    }
}

/// rustup toolchain names such as `1.94.0-aarch64-apple-darwin` or `nightly-2026-01-01-x86_64-unknown-linux-gnu`.
fn is_toolchain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('-')
        && !name.bytes().all(|b| b == b'.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// `sha256:` followed by exactly 64 lowercase hex digits (what `docker system df -v` reports).
fn is_docker_image_id(id: &str) -> bool {
    id.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Docker's volume name rule: `[a-zA-Z0-9][a-zA-Z0-9_.-]+`, at most 255 bytes.
fn is_docker_volume_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=255).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_snap_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// What happens when an item is cleaned.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CleanupAction {
    /// Remove `path` (to Trash or permanently, depending on the chosen mode).
    /// `root` is the directory `path` must live strictly inside.
    RemovePath { path: PathBuf, root: PathBuf },
    /// Permanently remove every entry inside `path`, keeping `path` itself.
    /// Used for trash folders, where moving to Trash is meaningless.
    EmptyDir { path: PathBuf, root: PathBuf },
    /// Run one of the fixed, known commands.
    Run(KnownCommand),
}

/// An app that must not be running while its data is cleaned (e.g. Slack for its cache).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunningApp {
    /// Name shown to the user ("Slack").
    pub app: String,
    /// Arguments to `pgrep` that match the app's processes, e.g. `["-f", "Slack.app/Contents/MacOS/"]`.
    pub pgrep: Vec<String>,
}

/// A single reclaimable item discovered by a scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier, unique within one scan.
    pub id: String,
    /// Identifier of the scanner that produced it.
    pub scanner: String,
    pub category: Category,
    pub title: String,
    /// Human explanation of what this is and what cleaning it does.
    pub detail: String,
    /// Location on disk, when the item maps to a path.
    pub path: Option<PathBuf>,
    /// Allocated bytes; `None` when the size cannot be determined.
    pub bytes: Option<u64>,
    pub risk: Risk,
    pub privilege: Privilege,
    /// `None` for informational findings that cannot be cleaned from the app.
    pub action: Option<CleanupAction>,
    /// Lower values win when two findings overlap on disk. Specific rules use 0, generic
    /// "every child of a cache folder" rules use 10.
    pub specificity: u8,
    /// Newest modification time inside the item (Unix seconds), when known.
    #[serde(default)]
    pub last_modified: Option<i64>,
    /// App that must be quit before cleaning; the cleaner refuses the item while it runs.
    #[serde(default)]
    pub quit_first: Option<RunningApp>,
}

impl Finding {
    pub const fn is_actionable(&self) -> bool {
        self.action.is_some()
    }

    /// Whole days since [`Finding::last_modified`], relative to `now` (Unix seconds).
    pub fn age_days(&self, now: i64) -> Option<u64> {
        self.last_modified.map(|t| u64::try_from((now - t).max(0) / 86_400).unwrap_or(0))
    }

    pub const fn bytes_or_zero(&self) -> u64 {
        match self.bytes {
            Some(b) => b,
            None => 0,
        }
    }
}

/// Specificity value for precise, hand-written rules.
pub const SPECIFIC: u8 = 0;
/// Specificity value for generic catch-all rules.
pub const GENERIC: u8 = 10;
/// Specificity of catch-all searches (large files): loses to every other rule on overlap.
pub const LOWEST: u8 = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_current_is_supported_on_ci_platforms() {
        assert!(Os::current().is_some());
    }

    #[test]
    fn category_all_has_unique_labels() {
        let mut labels: Vec<_> = Category::ALL.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), Category::ALL.len());
        assert_eq!(Category::Xcode.to_string(), "Xcode");
        assert_eq!(Category::DeveloperCaches.slug(), "developer-caches");
        for c in Category::ALL {
            assert_eq!(Category::from_slug(&c.slug()), Some(c));
        }
        assert_eq!(Category::from_slug("nope"), None);
    }

    #[test]
    fn docker_volume_prune_includes_named_volumes() {
        assert_eq!(KnownCommand::DockerPruneVolumes.argv(), ["docker", "volume", "prune", "--all", "--force"]);
    }

    #[test]
    fn snap_argv_includes_revision() {
        let cmd = KnownCommand::SnapRemoveRevision { name: "core22".into(), revision: "1033".into() };
        assert_eq!(cmd.argv(), ["snap", "remove", "core22", "--revision=1033"]);
        assert!(cmd.requires_admin());
        assert!(cmd.is_well_formed());
    }

    #[test]
    fn snap_rejects_injected_arguments() {
        for (name, rev) in
            [("--purge", "1"), ("core; rm -rf /", "1"), ("core", "1 --purge"), ("", "1"), ("core", ""), ("Core", "1")]
        {
            let cmd = KnownCommand::SnapRemoveRevision { name: name.into(), revision: rev.into() };
            assert!(!cmd.is_well_formed(), "{name:?} {rev:?} must be rejected");
        }
    }

    #[test]
    fn docker_item_removal_is_validated() {
        let id = format!("sha256:{}", "a1".repeat(32));
        let image = KnownCommand::DockerRemoveImage { id: id.clone() };
        assert_eq!(image.argv(), ["docker", "image", "rm", id.as_str()]);
        assert!(image.is_well_formed() && !image.requires_admin() && !image.is_docker_prune());
        let volume = KnownCommand::DockerRemoveVolume { name: "pg_data-1.x".into() };
        assert_eq!(volume.argv(), ["docker", "volume", "rm", "pg_data-1.x"]);
        assert!(volume.is_well_formed());
        for bad in [
            "",
            "sha256:",
            "sha256:XYZ",
            &format!("sha256:{}", "A1".repeat(32)),
            &format!("sha256:{}", "a".repeat(63)),
            "--all",
            "abc",
        ] {
            assert!(!KnownCommand::DockerRemoveImage { id: bad.into() }.is_well_formed(), "{bad:?}");
        }
        for bad in ["", "a", "-f", "--force", "_x", "a b", "a/b", "x;rm", &"a".repeat(256)] {
            assert!(!KnownCommand::DockerRemoveVolume { name: bad.into() }.is_well_formed(), "{bad:?}");
        }
    }

    #[test]
    fn rustup_uninstall_is_validated() {
        let ok = KnownCommand::RustupUninstall { toolchain: "1.94.0-aarch64-apple-darwin".into() };
        assert_eq!(ok.argv(), ["rustup", "toolchain", "uninstall", "1.94.0-aarch64-apple-darwin"]);
        assert!(ok.is_well_formed() && !ok.requires_admin());
        for bad in ["", "--all", "stable; rm -rf ~", "a b", "../x", ".", ".."] {
            assert!(!KnownCommand::RustupUninstall { toolchain: bad.into() }.is_well_formed(), "{bad:?}");
        }
    }

    #[test]
    fn admin_classification() {
        assert!(KnownCommand::AptClean.requires_admin());
        assert!(KnownCommand::TimeMachineDeleteLocalSnapshots.requires_admin());
        assert!(!KnownCommand::DockerPruneImages.requires_admin());
        assert!(!KnownCommand::BrewCleanup.requires_admin());
        assert!(KnownCommand::DockerPruneBuildCache.is_docker_prune());
        assert!(!KnownCommand::BrewCleanup.is_docker_prune());
        assert!(KnownCommand::BrewCleanup.is_well_formed());
    }

    #[test]
    fn every_command_has_a_program() {
        let all = [
            KnownCommand::DockerPruneImages,
            KnownCommand::DockerPruneContainers,
            KnownCommand::DockerPruneVolumes,
            KnownCommand::DockerPruneBuildCache,
            KnownCommand::BrewCleanup,
            KnownCommand::GoCleanModCache,
            KnownCommand::GoCleanBuildCache,
            KnownCommand::SimctlDeleteUnavailable,
            KnownCommand::FinderEmptyTrash,
            KnownCommand::TimeMachineDeleteLocalSnapshots,
            KnownCommand::JournalVacuum,
            KnownCommand::AptClean,
            KnownCommand::DnfClean,
            KnownCommand::PacmanClean,
        ];
        for cmd in all {
            let argv = cmd.argv();
            assert!(!argv.is_empty() && !argv[0].is_empty(), "{cmd:?}");
        }
    }

    #[test]
    fn bytes_or_zero_handles_unknown() {
        let mut f = Finding {
            id: "x".into(),
            scanner: "s".into(),
            category: Category::Logs,
            title: "t".into(),
            detail: String::new(),
            path: None,
            bytes: None,
            risk: Risk::Safe,
            privilege: Privilege::User,
            action: None,
            specificity: SPECIFIC,
            last_modified: None,
            quit_first: None,
        };
        assert_eq!(f.bytes_or_zero(), 0);
        assert!(!f.is_actionable());
        f.bytes = Some(42);
        f.action = Some(CleanupAction::Run(KnownCommand::BrewCleanup));
        assert_eq!(f.bytes_or_zero(), 42);
        assert!(f.is_actionable());
        assert_eq!(f.age_days(1_000_000), None);
        f.last_modified = Some(1_000_000 - 3 * 86_400 - 5);
        assert_eq!(f.age_days(1_000_000), Some(3));
        f.last_modified = Some(2_000_000);
        assert_eq!(f.age_days(1_000_000), Some(0), "future timestamps clamp to 0");
    }
}
