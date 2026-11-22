//! Path safety validation. Every path is validated when it is scanned and again immediately
//! before it is removed.

use std::io;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("path is not absolute: {0}")]
    NotAbsolute(PathBuf),
    #[error("path contains '..' components: {0}")]
    Traversal(PathBuf),
    #[error("path no longer exists: {0}")]
    NotFound(PathBuf),
    #[error("refusing to operate on a symbolic link: {0}")]
    IsSymlink(PathBuf),
    #[error("{path} is not strictly inside {root}")]
    OutsideRoot { path: PathBuf, root: PathBuf },
    #[error("{0} is (or contains) a protected location")]
    Protected(PathBuf),
    #[error("cannot inspect {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Set of locations that must never be removed, nor any of their ancestors.
#[derive(Debug, Clone)]
pub struct SafetyPolicy {
    protected: Vec<PathBuf>,
}

const SYSTEM_PROTECTED: &[&str] = &[
    "/",
    "/Applications",
    "/Library",
    "/System",
    "/Users",
    "/Volumes",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/nix",
    "/opt",
    "/private",
    "/proc",
    "/root",
    "/sbin",
    "/snap",
    "/srv",
    "/sys",
    "/usr",
    "/var",
    "/var/lib",
    "/var/log",
    "/Library/Caches",
    "/Library/Logs",
];

const HOME_PROTECTED: &[&str] = &[
    "",
    ".aws",
    ".cargo",
    ".config",
    ".docker",
    ".gnupg",
    ".kube",
    ".local",
    ".local/share",
    ".rustup",
    ".ssh",
    "Applications",
    "Desktop",
    "Documents",
    "Downloads",
    "Library",
    "Library/Application Support",
    "Library/Caches",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Keychains",
    "Library/Logs",
    "Library/Mail",
    "Library/Messages",
    "Library/Mobile Documents",
    "Library/Preferences",
    "Movies",
    "Music",
    "Pictures",
    "Public",
    "Videos",
    "go",
];

impl SafetyPolicy {
    /// Policy with an explicit protected list (used by tests and the privileged helper).
    pub fn new(protected: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut list = Vec::new();
        for p in protected {
            if let Ok(canonical) = p.canonicalize() {
                list.push(canonical);
            }
            list.push(p);
        }
        list.sort();
        list.dedup();
        Self { protected: list }
    }

    /// System locations only (used by the privileged helper, which has no user home).
    pub fn system() -> Self {
        Self::new(SYSTEM_PROTECTED.iter().map(PathBuf::from))
    }

    /// Standard policy: system locations plus the user's home and its important folders.
    pub fn for_home(home: &Path) -> Self {
        let system = SYSTEM_PROTECTED.iter().map(PathBuf::from);
        let user = HOME_PROTECTED.iter().map(|rel| if rel.is_empty() { home.to_path_buf() } else { home.join(rel) });
        Self::new(system.chain(user))
    }

    /// Validates that `path` may be removed: it must exist, must not be a symlink, must live
    /// strictly inside `root` after resolving symlinks in its ancestors, and must not be (or
    /// contain) a protected location. Returns the canonical path.
    pub fn validate(&self, path: &Path, root: &Path) -> Result<PathBuf, SafetyError> {
        for p in [path, root] {
            if !p.is_absolute() {
                return Err(SafetyError::NotAbsolute(p.to_path_buf()));
            }
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(SafetyError::Traversal(p.to_path_buf()));
            }
        }
        let meta = std::fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
        if meta.file_type().is_symlink() {
            return Err(SafetyError::IsSymlink(path.to_path_buf()));
        }
        let canonical = path.canonicalize().map_err(|e| io_error(path, e))?;
        let canonical_root = root.canonicalize().map_err(|e| io_error(root, e))?;
        if canonical == canonical_root || !canonical.starts_with(&canonical_root) {
            return Err(SafetyError::OutsideRoot { path: canonical, root: canonical_root });
        }
        if self.is_protected(&canonical) || self.is_protected(path) {
            return Err(SafetyError::Protected(canonical));
        }
        Ok(canonical)
    }

    /// True when `path` equals or is an ancestor of a protected location.
    pub fn is_protected(&self, path: &Path) -> bool {
        self.protected.iter().any(|p| p.starts_with(path))
    }
}

fn io_error(path: &Path, source: io::Error) -> SafetyError {
    if source.kind() == io::ErrorKind::NotFound {
        SafetyError::NotFound(path.to_path_buf())
    } else {
        SafetyError::Io { path: path.to_path_buf(), source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical").join("cache");
        fs::create_dir_all(root.join("app/nested")).expect("mkdir");
        fs::write(root.join("app/nested/file.bin"), b"data").expect("write");
        (dir, root)
    }

    fn open_policy() -> SafetyPolicy {
        SafetyPolicy::new(Vec::new())
    }

    #[test]
    fn accepts_path_strictly_inside_root() {
        let (_d, root) = fixture();
        let ok = open_policy().validate(&root.join("app"), &root).expect("valid");
        assert_eq!(ok, root.join("app"));
        assert!(open_policy().validate(&root.join("app/nested/file.bin"), &root).is_ok());
    }

    #[test]
    fn rejects_root_itself_and_outside_paths() {
        let (d, root) = fixture();
        assert!(matches!(open_policy().validate(&root, &root), Err(SafetyError::OutsideRoot { .. })));
        let outside = d.path().join("elsewhere");
        fs::create_dir(&outside).expect("mkdir");
        assert!(matches!(open_policy().validate(&outside, &root), Err(SafetyError::OutsideRoot { .. })));
    }

    #[test]
    fn rejects_relative_and_traversal() {
        let (_d, root) = fixture();
        assert!(matches!(open_policy().validate(Path::new("cache/app"), &root), Err(SafetyError::NotAbsolute(_))));
        assert!(matches!(open_policy().validate(&root.join("app/../app"), &root), Err(SafetyError::Traversal(_))));
        assert!(matches!(
            open_policy().validate(&root.join("app"), Path::new("cache")),
            Err(SafetyError::NotAbsolute(_))
        ));
    }

    #[test]
    fn rejects_missing_paths() {
        let (_d, root) = fixture();
        assert!(matches!(open_policy().validate(&root.join("missing"), &root), Err(SafetyError::NotFound(_))));
    }

    #[test]
    fn rejects_symlink_targets() {
        let (_d, root) = fixture();
        let link = root.join("link");
        symlink(root.join("app"), &link).expect("symlink");
        assert!(matches!(open_policy().validate(&link, &root), Err(SafetyError::IsSymlink(_))));
    }

    #[test]
    fn rejects_escape_through_symlinked_parent() {
        let (d, root) = fixture();
        let outside = d.path().join("outside");
        fs::create_dir_all(outside.join("victim")).expect("mkdir");
        symlink(&outside, root.join("escape")).expect("symlink");
        let err = open_policy().validate(&root.join("escape/victim"), &root);
        assert!(matches!(err, Err(SafetyError::OutsideRoot { .. })), "{err:?}");
    }

    #[test]
    fn rejects_protected_and_ancestors_of_protected() {
        let (_d, root) = fixture();
        let policy = SafetyPolicy::new([root.join("app/nested")]);
        assert!(matches!(policy.validate(&root.join("app"), &root), Err(SafetyError::Protected(_))));
        assert!(matches!(policy.validate(&root.join("app/nested"), &root), Err(SafetyError::Protected(_))));
        assert!(policy.validate(&root.join("app/nested/file.bin"), &root).is_ok());
    }

    #[test]
    fn home_policy_protects_key_locations() {
        let home = Path::new("/Users/alice");
        let policy = SafetyPolicy::for_home(home);
        for p in ["/", "/Users", "/Users/alice", "/Users/alice/Documents", "/usr", "/Library/Caches"] {
            assert!(policy.is_protected(Path::new(p)), "{p} should be protected");
        }
        for p in [
            "/Users/alice/Library/Caches/com.spotify.client",
            "/Users/alice/.cargo/registry",
            "/Users/alice/Documents/project/target",
            "/Library/Caches/com.apple.iconservices",
        ] {
            assert!(!policy.is_protected(Path::new(p)), "{p} should be removable");
        }
    }

    #[test]
    fn io_errors_other_than_not_found_are_reported() {
        let err = io_error(Path::new("/x"), io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(err, SafetyError::Io { .. }));
        assert!(err.to_string().contains("/x"));
    }
}
