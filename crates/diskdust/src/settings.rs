//! User settings persisted between launches: project folders, delete mode, age filter and
//! ignored items. Stored as JSON in the platform config folder
//! (`~/Library/Application Support/diskdust/settings.json` on macOS,
//! `$XDG_CONFIG_HOME/diskdust/settings.json` on Linux).

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;

use diskdust_core::clean::DeleteMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `None` until the user changes the list; then the defaults are no longer applied.
    pub project_roots: Option<Vec<PathBuf>>,
    pub mode: Option<DeleteMode>,
    pub older_than: Option<u32>,
    /// Finding ids hidden from results, cleaning and totals.
    pub ignored: BTreeSet<String>,
}

/// Where settings are read from and written to. `None` keeps them in memory only (tests).
#[derive(Debug, Clone)]
pub struct SettingsStore {
    path: Option<PathBuf>,
}

impl SettingsStore {
    pub fn default_location() -> Self {
        Self { path: dirs::config_dir().map(|dir| dir.join("diskdust/settings.json")) }
    }

    #[cfg(test)]
    pub fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    #[cfg(test)]
    pub const fn in_memory() -> Self {
        Self { path: None }
    }

    #[cfg(test)]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Loads settings; a missing file yields defaults, a corrupt one is logged and ignored.
    pub fn load(&self) -> Settings {
        let Some(path) = &self.path else { return Settings::default() };
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!(error = %e, path = %path.display(), "ignoring unreadable settings file");
                Settings::default()
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Settings::default(),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "could not read settings");
                Settings::default()
            }
        }
    }

    /// Writes settings atomically (temporary file + rename).
    pub fn save(&self, settings: &Settings) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(settings).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SettingsStore::at(dir.path().join("nested/settings.json"));
        assert_eq!(store.load(), Settings::default(), "missing file means defaults");
        let settings = Settings {
            project_roots: Some(vec![PathBuf::from("/x/code")]),
            mode: Some(DeleteMode::Permanent),
            older_than: Some(30),
            ignored: ["docker:Images".to_owned()].into(),
        };
        store.save(&settings).expect("save");
        assert_eq!(store.load(), settings);
        assert!(!dir.path().join("nested/settings.json.tmp").exists());
    }

    #[test]
    fn corrupt_or_partial_files_fall_back_to_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        fs::write(&path, b"{not json").expect("write");
        assert_eq!(SettingsStore::at(path.clone()).load(), Settings::default());
        fs::write(&path, br#"{"older_than": 7}"#).expect("write");
        assert_eq!(SettingsStore::at(path).load().older_than, Some(7));
    }

    #[test]
    fn in_memory_store_never_touches_disk() {
        let store = SettingsStore::in_memory();
        assert!(store.path().is_none());
        store.save(&Settings::default()).expect("noop");
        assert_eq!(store.load(), Settings::default());
        assert!(SettingsStore::default_location().path().is_some_and(|p| p.ends_with("diskdust/settings.json")));
    }
}
