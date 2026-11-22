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
}

impl Category {
    pub const ALL: [Self; 10] = [
        Self::Containers,
        Self::DeveloperCaches,
        Self::BuildArtifacts,
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
        }
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
    SnapRemoveRevision { name: String, revision: String },
    FlatpakUninstallUnused,
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
            Self::FlatpakUninstallUnused => &["flatpak", "uninstall", "--unused", "-y"],
            Self::SnapRemoveRevision { name, revision } => {
                return vec!["snap".to_owned(), "remove".to_owned(), name.clone(), format!("--revision={revision}")];
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
            _ => true,
        }
    }
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
}

impl Finding {
    pub const fn is_actionable(&self) -> bool {
        self.action.is_some()
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
            KnownCommand::FlatpakUninstallUnused,
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
        };
        assert_eq!(f.bytes_or_zero(), 0);
        assert!(!f.is_actionable());
        f.bytes = Some(42);
        f.action = Some(CleanupAction::Run(KnownCommand::BrewCleanup));
        assert_eq!(f.bytes_or_zero(), 42);
        assert!(f.is_actionable());
    }
}
