//! Privilege elevation for admin-only cleanups.
//!
//! The GUI never runs as root. Admin actions are serialized, hex-encoded (so the payload needs no
//! shell or `AppleScript` escaping) and passed to `diskdust helper <payload>`, launched through the
//! OS-native authorization prompt. The helper ignores any root directory sent by the caller and
//! validates every action against its own fixed allowlist.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::clean::{Cleaner, DeleteMode, Trasher};
use crate::command::CommandRunner;
use crate::model::{CleanupAction, Os};
use crate::mounts::MountTable;
use crate::safety::SafetyPolicy;

/// Subcommand used to invoke the helper.
pub const HELPER_SUBCOMMAND: &str = "helper";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("payload is not valid hex")]
    Hex,
    #[error("payload is not a valid action list: {0}")]
    Json(String),
    #[error("could not encode the action list: {0}")]
    Encode(String),
}

/// Result of one action executed by the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResult {
    pub ok: bool,
    pub message: String,
}

/// Directories the helper may remove children from.
pub fn admin_roots(os: Os) -> Vec<PathBuf> {
    match os {
        Os::MacOs => vec![PathBuf::from("/Library/Caches"), PathBuf::from("/Library/Logs")],
        Os::Linux => Vec::new(),
    }
}

pub fn encode_payload(actions: &[CleanupAction]) -> Result<String, PayloadError> {
    let json = serde_json::to_vec(actions).map_err(|e| PayloadError::Encode(e.to_string()))?;
    let mut out = String::with_capacity(json.len() * 2);
    for byte in json {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// The program to launch as the helper.
///
/// Inside a Linux `AppImage`, `current_exe()` lives in the user's FUSE mount, which root cannot
/// open; the `AppImage` file itself (`$APPIMAGE`) is executable by root, so it is used instead when
/// it is an absolute path to an existing regular file.
pub fn helper_executable(current_exe: PathBuf, appimage: Option<&OsStr>) -> PathBuf {
    appimage
        .map(Path::new)
        .filter(|p| p.is_absolute() && std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file()))
        .map_or(current_exe, Path::to_path_buf)
}

pub fn decode_payload(hex: &str) -> Result<Vec<CleanupAction>, PayloadError> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PayloadError::Hex);
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| PayloadError::Hex))
        .collect::<Result<_, _>>()?;
    serde_json::from_slice(&bytes).map_err(|e| PayloadError::Json(e.to_string()))
}

/// Whether the helper may perform `action`, given the fixed `roots` allowlist.
pub fn validate_admin_action(action: &CleanupAction, roots: &[PathBuf]) -> Result<(), String> {
    match action {
        CleanupAction::RemovePath { root, .. } | CleanupAction::EmptyDir { root, .. } => {
            if roots.iter().any(|r| r == root) {
                Ok(())
            } else {
                Err(format!("{} is not an allowed admin location", root.display()))
            }
        }
        CleanupAction::Run(cmd) if cmd.requires_admin() && cmd.is_well_formed() => Ok(()),
        CleanupAction::Run(_) => Err("command is not an allowed admin command".to_owned()),
    }
}

/// Helper entry point: validates and executes every action permanently.
pub fn run_helper(
    payload: &str,
    roots: &[PathBuf],
    runner: &dyn CommandRunner,
    trasher: &dyn Trasher,
) -> Result<Vec<HelperResult>, PayloadError> {
    let actions = decode_payload(payload)?;
    let policy = SafetyPolicy::system();
    let mounts = MountTable::current(Os::current().unwrap_or(Os::Linux), runner);
    let cleaner =
        Cleaner { policy: &policy, runner, trasher, mode: DeleteMode::Permanent, allow_admin: true, mounts: &mounts };
    Ok(actions
        .iter()
        .map(|action| {
            match validate_admin_action(action, roots).and_then(|()| cleaner.execute(action).map_err(|e| e.to_string()))
            {
                Ok(message) => HelperResult { ok: true, message },
                Err(message) => HelperResult { ok: false, message },
            }
        })
        .collect())
}

/// Serializes helper results as JSON lines.
pub fn format_helper_output(results: &[HelperResult]) -> String {
    results.iter().filter_map(|r| serde_json::to_string(r).ok()).map(|l| l + "\n").collect()
}

/// Parses helper stdout, padding with failures if fewer than `expected` results came back.
pub fn parse_helper_output(stdout: &str, expected: usize) -> Vec<HelperResult> {
    let mut results: Vec<HelperResult> =
        stdout.split(['\n', '\r']).filter_map(|l| serde_json::from_str(l.trim()).ok()).take(expected).collect();
    while results.len() < expected {
        results.push(HelperResult { ok: false, message: "helper returned no result".to_owned() });
    }
    results
}

/// POSIX single-quote shell escaping.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// `AppleScript` string literal escaping.
fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

/// Command that launches the helper through the OS authorization prompt.
pub fn elevation_argv(os: Os, exe: &Path, payload: &str) -> Vec<String> {
    let exe = exe.to_string_lossy();
    match os {
        Os::MacOs => {
            let shell = format!("{} {HELPER_SUBCOMMAND} {payload}", shell_quote(&exe));
            let script = format!(
                "do shell script {} with prompt \"diskdust needs administrator access to clean system items.\" \
                 with administrator privileges without altering line endings",
                applescript_quote(&shell)
            );
            vec!["osascript".to_owned(), "-e".to_owned(), script]
        }
        Os::Linux => vec!["pkexec".to_owned(), exe.into_owned(), HELPER_SUBCOMMAND.to_owned(), payload.to_owned()],
    }
}

/// Friendly explanation for a failed elevation attempt.
pub fn describe_elevation_failure(os: Os, code: Option<i32>, stderr: &str) -> String {
    match os {
        Os::MacOs if stderr.contains("-128") => "Authorization was cancelled.".to_owned(),
        Os::Linux if code == Some(126) => "Authorization was cancelled.".to_owned(),
        Os::Linux if code == Some(127) => {
            "Not authorized: your account is not an administrator, or no polkit agent is running.".to_owned()
        }
        _ => format!("Could not obtain administrator access: {}", stderr.trim()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::tests::RecordingTrash;
    use crate::command::fake::FakeRunner;
    use crate::model::KnownCommand;
    use crate::scanners::testutil::write_file;

    #[test]
    fn payload_round_trip() {
        let actions = vec![
            CleanupAction::Run(KnownCommand::AptClean),
            CleanupAction::RemovePath { path: "/Library/Caches/it's \"odd\"".into(), root: "/Library/Caches".into() },
        ];
        let hex = encode_payload(&actions).expect("encode");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(decode_payload(&hex).expect("decode"), actions);
    }

    #[test]
    fn payload_rejects_bad_input() {
        assert_eq!(decode_payload("abc"), Err(PayloadError::Hex));
        assert_eq!(decode_payload("zz"), Err(PayloadError::Hex));
        assert!(matches!(decode_payload("7b7d"), Err(PayloadError::Json(_))));
    }

    #[test]
    fn admin_validation_uses_fixed_roots() {
        let roots = admin_roots(Os::MacOs);
        let ok = CleanupAction::RemovePath { path: "/Library/Caches/x".into(), root: "/Library/Caches".into() };
        assert!(validate_admin_action(&ok, &roots).is_ok());
        let sneaky = CleanupAction::RemovePath { path: "/etc/passwd".into(), root: "/etc".into() };
        assert!(validate_admin_action(&sneaky, &roots).is_err());
        let user_cmd = CleanupAction::Run(KnownCommand::DockerPruneImages);
        assert!(validate_admin_action(&user_cmd, &roots).is_err());
        assert!(validate_admin_action(&CleanupAction::Run(KnownCommand::JournalVacuum), &roots).is_ok());
        assert!(admin_roots(Os::Linux).is_empty());
    }

    #[test]
    fn helper_executes_allowed_and_refuses_others() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical").join("Caches");
        write_file(&root.join("vendor/blob"), 10);
        let outside = write_file(&dir.path().join("keep/me"), 10);
        let actions = vec![
            CleanupAction::RemovePath { path: root.join("vendor"), root: root.clone() },
            CleanupAction::RemovePath { path: outside.clone(), root: dir.path().join("keep") },
            CleanupAction::Run(KnownCommand::BrewCleanup),
        ];
        let runner = FakeRunner::new().installed("brew").respond("mount", true, "/dev/disk3s1 on / (apfs, local)\n");
        let results = run_helper(
            &encode_payload(&actions).expect("encode"),
            std::slice::from_ref(&root),
            &runner,
            &RecordingTrash::default(),
        )
        .expect("run");
        assert!(results[0].ok, "{results:?}");
        assert!(!root.join("vendor").exists());
        assert!(!results[1].ok);
        assert!(outside.exists());
        assert!(!results[2].ok);
        let calls = runner.calls.lock().expect("lock").clone();
        assert!(calls.iter().all(|c| c == "mount"), "the refused brew command must never run: {calls:?}");
        assert!(run_helper("xyz", &[], &runner, &RecordingTrash::default()).is_err());
    }

    #[test]
    fn helper_output_round_trip_and_padding() {
        let results =
            vec![HelperResult { ok: true, message: "a".into() }, HelperResult { ok: false, message: "b".into() }];
        let text = format_helper_output(&results).replace('\n', "\r");
        assert_eq!(parse_helper_output(&text, 2), results);
        let padded = parse_helper_output("garbage", 1);
        assert_eq!(padded.len(), 1);
        assert!(!padded[0].ok);
    }

    #[test]
    fn elevation_commands() {
        let mac = elevation_argv(Os::MacOs, Path::new("/Users/a b/it's/diskdust"), "7b7d");
        assert_eq!(mac[0], "osascript");
        assert!(mac[2].starts_with("do shell script \"'/Users/a b/it'\\\\''s/diskdust' helper 7b7d\""), "{}", mac[2]);
        assert!(mac[2].ends_with("without altering line endings"));
        let linux = elevation_argv(Os::Linux, Path::new("/opt/diskdust"), "7b7d");
        assert_eq!(linux, ["pkexec", "/opt/diskdust", "helper", "7b7d"]);
    }

    #[test]
    fn helper_executable_prefers_a_real_appimage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = write_file(&dir.path().join("diskdust.AppImage"), 10);
        let exe = PathBuf::from("/tmp/.mount_abc/usr/bin/diskdust");
        assert_eq!(helper_executable(exe.clone(), Some(image.as_os_str())), image);
        assert_eq!(helper_executable(exe.clone(), None), exe);
        assert_eq!(helper_executable(exe.clone(), Some(OsStr::new("relative.AppImage"))), exe);
        assert_eq!(helper_executable(exe.clone(), Some(dir.path().join("missing").as_os_str())), exe);
        assert_eq!(helper_executable(exe.clone(), Some(dir.path().as_os_str())), exe, "directories are refused");
    }

    #[test]
    fn quoting_helpers() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(applescript_quote(r#"x\"y"#), r#""x\\\"y""#);
    }

    #[test]
    fn elevation_failures_are_explained() {
        assert_eq!(
            describe_elevation_failure(Os::MacOs, Some(1), "execution error: User canceled. (-128)"),
            "Authorization was cancelled."
        );
        assert_eq!(describe_elevation_failure(Os::Linux, Some(126), ""), "Authorization was cancelled.");
        assert!(describe_elevation_failure(Os::Linux, Some(127), "").starts_with("Not authorized"));
        assert!(describe_elevation_failure(Os::Linux, Some(1), " boom ").ends_with("boom"));
    }
}
