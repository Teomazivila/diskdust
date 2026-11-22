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
    /// Identifier shared by every entry of one clean run (empty in logs written before it existed).
    #[serde(default)]
    pub run_id: String,
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

    /// New run identifier: UTC nanoseconds and process id in hex, e.g. `18a2f3c4d5e6f708-1f2a`.
    pub fn new_run_id() -> String {
        let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
        format!("{nanos:x}-{:x}", std::process::id())
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

    /// Up to `limit` most recent entries, newest first. A missing log is empty; malformed lines
    /// are skipped.
    pub fn read_recent(&self, limit: usize) -> io::Result<Vec<AuditEntry>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        Ok(text.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(limit).collect())
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
            run_id: "run-1".into(),
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
    fn run_ids_are_unique_and_old_entries_still_parse() {
        let a = AuditEntry::new_run_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_ne!(a, AuditEntry::new_run_id());
        assert!(a.contains('-'));
        let mut legacy = serde_json::to_value(entry(true)).expect("json");
        legacy.as_object_mut().expect("object").remove("run_id");
        let parsed: AuditEntry = serde_json::from_value(legacy).expect("legacy entry");
        assert_eq!(parsed.run_id, "");
    }

    #[test]
    fn reads_recent_entries_newest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("cleanup.jsonl"));
        assert!(log.read_recent(5).expect("missing log").is_empty());
        for (i, ok) in [true, false, true].into_iter().enumerate() {
            let mut e = entry(ok);
            e.finding_id = format!("f{i}");
            log.append(&e).expect("append");
        }
        fs::OpenOptions::new().append(true).open(log.path()).expect("open").write_all(b"not json\n").expect("write");
        let recent = log.read_recent(2).expect("read");
        let ids: Vec<_> = recent.iter().map(|e| e.finding_id.as_str()).collect();
        assert_eq!(ids, ["f2", "f1"]);
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
