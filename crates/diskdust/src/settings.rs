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

/// Result of [`SettingsStore::load`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    pub settings: Settings,
    /// Set when the file exists but could not be fully read; unread fields fell back to defaults.
    pub problem: Option<String>,
}

impl Loaded {
    fn problem(problem: String) -> Self {
        Self { settings: Settings::default(), problem: Some(problem) }
    }
}

/// Decodes one optional field; a present but invalid value is recorded in `bad`.
fn field<T: serde::de::DeserializeOwned>(
    map: &serde_json::Map<String, serde_json::Value>,
    name: &'static str,
    bad: &mut Vec<&'static str>,
) -> Option<T> {
    let value = map.get(name).filter(|v| !v.is_null())?;
    serde_json::from_value(value.clone()).map_err(|_| bad.push(name)).ok()
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

    /// Loads settings. A missing file yields defaults. Each field is decoded on its own, so one
    /// bad value does not discard the others (in particular the ignore list); anything that could
    /// not be read is described in [`Loaded::problem`].
    pub fn load(&self) -> Loaded {
        let Some(path) = &self.path else { return Loaded::default() };
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Loaded::default(),
            Err(e) => return Loaded::problem(format!("could not read {}: {e}", path.display())),
        };
        let map = match serde_json::from_slice(&bytes) {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => return Loaded::problem(format!("{} is not a JSON object", path.display())),
            Err(e) => return Loaded::problem(format!("{} is not valid JSON: {e}", path.display())),
        };
        let mut bad = Vec::new();
        let settings = Settings {
            project_roots: field(&map, "project_roots", &mut bad),
            mode: field(&map, "mode", &mut bad),
            older_than: field(&map, "older_than", &mut bad),
            ignored: field(&map, "ignored", &mut bad).unwrap_or_default(),
        };
        let problem = (!bad.is_empty()).then(|| format!("{}: could not read {}", path.display(), bad.join(", ")));
        Loaded { settings, problem }
    }

    /// Copies an unreadable settings file to `settings.json.bad` so a later save cannot destroy
    /// what the user had in it. Returns the backup path.
    pub fn back_up(&self) -> io::Result<Option<PathBuf>> {
        let Some(path) = &self.path else { return Ok(None) };
        if !path.exists() {
            return Ok(None);
        }
        let backup = path.with_extension("json.bad");
        fs::copy(path, &backup)?;
        Ok(Some(backup))
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
        assert_eq!(store.load(), Loaded::default(), "missing file means defaults, no problem");
        let settings = Settings {
            project_roots: Some(vec![PathBuf::from("/x/code")]),
            mode: Some(DeleteMode::Permanent),
            older_than: Some(30),
            ignored: ["docker:Images".to_owned()].into(),
        };
        store.save(&settings).expect("save");
        assert_eq!(store.load(), Loaded { settings, problem: None });
        assert!(!dir.path().join("nested/settings.json.tmp").exists());
    }

    #[test]
    fn corrupt_files_are_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        for bad in [&b"{not json"[..], b"[1, 2]"] {
            fs::write(&path, bad).expect("write");
            let loaded = SettingsStore::at(path.clone()).load();
            assert_eq!(loaded.settings, Settings::default());
            assert!(loaded.problem.is_some(), "{bad:?}");
        }
    }

    #[test]
    fn one_bad_field_keeps_the_ignore_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        fs::write(&path, br#"{"ignored":["trash:user","docker:Images"],"older_than":-1,"mode":null}"#).expect("write");
        let loaded = SettingsStore::at(path.clone()).load();
        assert_eq!(loaded.settings.ignored, ["docker:Images".to_owned(), "trash:user".to_owned()].into());
        assert_eq!(loaded.settings.older_than, None);
        assert!(loaded.problem.as_deref().is_some_and(|p| p.ends_with("could not read older_than")), "{loaded:?}");
        fs::write(&path, br#"{"older_than": 7}"#).expect("write");
        assert_eq!(
            SettingsStore::at(path).load(),
            Loaded { settings: Settings { older_than: Some(7), ..Settings::default() }, problem: None }
        );
    }

    #[test]
    fn unreadable_ignore_list_is_a_problem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        fs::write(&path, br#"{"ignored":"trash:user"}"#).expect("write");
        let store = SettingsStore::at(path.clone());
        let loaded = store.load();
        assert!(loaded.settings.ignored.is_empty());
        assert!(loaded.problem.as_deref().is_some_and(|p| p.contains("ignored")));
        let backup = store.back_up().expect("backup").expect("path");
        assert_eq!(fs::read(&backup).expect("read"), fs::read(&path).expect("read"));
        assert!(backup.ends_with("settings.json.bad"));
    }

    #[test]
    fn in_memory_store_never_touches_disk() {
        let store = SettingsStore::in_memory();
        assert!(store.path().is_none());
        store.save(&Settings::default()).expect("noop");
        assert_eq!(store.load(), Loaded::default());
        assert!(store.back_up().expect("noop").is_none());
        assert!(SettingsStore::default_location().path().is_some_and(|p| p.ends_with("diskdust/settings.json")));
    }
}
