//! Append-only JSON Lines log of every cleanup attempt.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::clean::DeleteMode;
use crate::model::{CleanupAction, Os};

/// One logged cleanup attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub finding_id: String,
    pub title: String,
    pub path: Option<PathBuf>,
    pub bytes: Option<u64>,
    pub action: CleanupAction,
    pub mode: DeleteMode,
    pub elevated: bool,
    pub ok: bool,
    pub message: String,
}

impl AuditEntry {
    /// Current UTC time in RFC 3339.
    pub fn now() -> String {
        OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// `~/Library/Logs/diskdust/cleanup.jsonl` on macOS,
    /// `$XDG_STATE_HOME/diskdust/cleanup.jsonl` (default `~/.local/state`) on Linux.
    pub fn default_location(home: &Path, os: Os, xdg_state_home: Option<PathBuf>) -> Self {
        let dir = match os {
            Os::MacOs => home.join("Library/Logs/diskdust"),
            Os::Linux => {
                xdg_state_home.filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(".local/state")).join("diskdust")
            }
        };
        Self::new(dir.join("cleanup.jsonl"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, entry: &AuditEntry) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(entry).map_err(io::Error::other)?;
        line.push('\n');
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(line.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::KnownCommand;

    fn entry(ok: bool) -> AuditEntry {
        AuditEntry {
            timestamp: AuditEntry::now(),
            finding_id: "docker:Build Cache".into(),
            title: "Docker build cache".into(),
            path: None,
            bytes: Some(10),
            action: CleanupAction::Run(KnownCommand::DockerPruneBuildCache),
            mode: DeleteMode::Trash,
            elevated: false,
            ok,
            message: "done".into(),
        }
    }

    #[test]
    fn appends_json_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("nested/cleanup.jsonl"));
        log.append(&entry(true)).expect("append");
        log.append(&entry(false)).expect("append");
        let text = fs::read_to_string(log.path()).expect("read");
        let parsed: Vec<AuditEntry> = text.lines().map(|l| serde_json::from_str(l).expect("json")).collect();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].ok && !parsed[1].ok);
        assert!(parsed[0].timestamp.contains('T'));
    }

    #[test]
    fn default_locations() {
        let home = Path::new("/home/u");
        assert_eq!(
            AuditLog::default_location(home, Os::MacOs, None).path(),
            Path::new("/home/u/Library/Logs/diskdust/cleanup.jsonl")
        );
        assert_eq!(
            AuditLog::default_location(home, Os::Linux, None).path(),
            Path::new("/home/u/.local/state/diskdust/cleanup.jsonl")
        );
        assert_eq!(
            AuditLog::default_location(home, Os::Linux, Some("/xdg".into())).path(),
            Path::new("/xdg/diskdust/cleanup.jsonl")
        );
        assert_eq!(
            AuditLog::default_location(home, Os::Linux, Some("relative".into())).path(),
            Path::new("/home/u/.local/state/diskdust/cleanup.jsonl")
        );
    }
}
