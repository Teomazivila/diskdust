//! Weekly read-only report: a per-user `LaunchAgent` (macOS) or systemd user timer (Linux) that
//! runs `diskdust report --notify`. Nothing is ever cleaned on a schedule.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use diskdust_core::command::CommandRunner;
use diskdust_core::model::Os;

pub const LABEL: &str = "dev.diskdust.report";
const SYSTEMD_UNIT: &str = "diskdust-report";
/// Monday (launchd weekday 1) at 10:00 local time.
const WEEKDAY: i64 = 1;
const HOUR: i64 = 10;

/// Files the schedule consists of.
pub fn files(os: Os, home: &Path) -> Vec<PathBuf> {
    match os {
        Os::MacOs => vec![home.join(format!("Library/LaunchAgents/{LABEL}.plist"))],
        Os::Linux => {
            let dir = home.join(".config/systemd/user");
            vec![dir.join(format!("{SYSTEMD_UNIT}.service")), dir.join(format!("{SYSTEMD_UNIT}.timer"))]
        }
    }
}

pub fn is_installed(os: Os, home: &Path) -> bool {
    files(os, home).iter().all(|f| f.is_file())
}

/// The `LaunchAgent` property list (generated with the `plist` crate, so paths are escaped).
pub fn launch_agent(exe: &Path) -> plist::Value {
    use plist::{Dictionary, Value};
    let mut calendar = Dictionary::new();
    calendar.insert("Weekday".into(), Value::Integer(WEEKDAY.into()));
    calendar.insert("Hour".into(), Value::Integer(HOUR.into()));
    calendar.insert("Minute".into(), Value::Integer(0.into()));
    let mut dict = Dictionary::new();
    dict.insert("Label".into(), Value::String(LABEL.into()));
    dict.insert(
        "ProgramArguments".into(),
        Value::Array(vec![
            Value::String(exe.to_string_lossy().into_owned()),
            Value::String("report".into()),
            Value::String("--notify".into()),
        ]),
    );
    dict.insert("StartCalendarInterval".into(), Value::Dictionary(calendar));
    dict.insert("ProcessType".into(), Value::String("Background".into()));
    dict.insert("LowPriorityIO".into(), Value::Boolean(true));
    dict.insert("Nice".into(), Value::Integer(10.into()));
    Value::Dictionary(dict)
}

/// Quotes one systemd `ExecStart=` argument: `\` and `"` escaped, `%` doubled (specifier).
fn systemd_quote(arg: &str) -> String {
    format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%"))
}

/// The systemd user `.service` and `.timer` units.
pub fn systemd_units(exe: &Path) -> (String, String) {
    let service = format!(
        "[Unit]\nDescription=diskdust weekly disk space report (read-only)\n\n\
         [Service]\nType=oneshot\nExecStart={} report --notify\nNice=10\nIOSchedulingClass=idle\n",
        systemd_quote(&exe.to_string_lossy())
    );
    let timer = format!(
        "[Unit]\nDescription=Run the diskdust report weekly\n\n\
         [Timer]\nOnCalendar=Mon *-*-* {HOUR:02}:00:00\nPersistent=true\n\n\
         [Install]\nWantedBy=timers.target\n"
    );
    (service, timer)
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

fn run(runner: &dyn CommandRunner, parts: &[&str]) -> Result<(), String> {
    let out = runner.run(&argv(parts), Duration::from_secs(30)).map_err(|e| e.to_string())?;
    if out.success { Ok(()) } else { Err(format!("`{}` failed: {}", parts.join(" "), out.stderr.trim())) }
}

fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

/// Installs (or refreshes) the weekly report for `exe` and activates it. If activation fails, the
/// written files are removed again so [`is_installed`] never reports an inactive schedule.
pub fn install(os: Os, home: &Path, exe: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    let result = write_and_activate(os, home, exe, runner);
    if result.is_err() {
        for path in files(os, home) {
            let _ = fs::remove_file(path);
        }
    }
    result
}

fn write_and_activate(os: Os, home: &Path, exe: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    let paths = files(os, home);
    match os {
        Os::MacOs => {
            let plist_path = &paths[0];
            let mut bytes = Vec::new();
            launch_agent(exe).to_writer_xml(&mut bytes).map_err(|e| e.to_string())?;
            write(plist_path, &bytes).map_err(|e| format!("cannot write {}: {e}", plist_path.display()))?;
            let domain = format!("gui/{}", uid());
            // Replace a previously loaded copy; "not loaded" is expected and ignored.
            let _ = run(runner, &["launchctl", "bootout", &format!("{domain}/{LABEL}")]);
            run(runner, &["launchctl", "bootstrap", &domain, &plist_path.to_string_lossy()])
        }
        Os::Linux => {
            let (service, timer) = systemd_units(exe);
            for (path, text) in paths.iter().zip([service, timer]) {
                write(path, text.as_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            }
            run(runner, &["systemctl", "--user", "daemon-reload"])?;
            run(runner, &["systemctl", "--user", "enable", "--now", &format!("{SYSTEMD_UNIT}.timer")])
        }
    }
}

/// Deactivates and deletes the weekly report.
pub fn remove(os: Os, home: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    match os {
        Os::MacOs => {
            let _ = run(runner, &["launchctl", "bootout", &format!("gui/{}/{LABEL}", uid())]);
        }
        Os::Linux => {
            let _ = run(runner, &["systemctl", "--user", "disable", "--now", &format!("{SYSTEMD_UNIT}.timer")]);
        }
    }
    for path in files(os, home) {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot remove {}: {e}", path.display())),
        }
    }
    if os == Os::Linux {
        let _ = run(runner, &["systemctl", "--user", "daemon-reload"]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diskdust_core::command::{CommandError, CommandOutput};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<String>>,
        fail: Option<&'static str>,
    }

    impl CommandRunner for Recorder {
        fn run(&self, argv: &[String], _timeout: Duration) -> Result<CommandOutput, CommandError> {
            let line = argv.join(" ");
            let success = self.fail.is_none_or(|f| !line.contains(f));
            self.calls.lock().expect("lock").push(line);
            Ok(CommandOutput { success, code: Some(i32::from(!success)), stdout: String::new(), stderr: "boom".into() })
        }

        fn exists(&self, _program: &str) -> bool {
            true
        }
    }

    #[test]
    fn launch_agent_runs_the_report_weekly() {
        let exe = Path::new("/Applications/disk & dust.app/Contents/MacOS/diskdust");
        let value = launch_agent(exe);
        let dict = value.as_dictionary().expect("dict");
        assert_eq!(dict.get("Label").and_then(plist::Value::as_string), Some(LABEL));
        let args: Vec<_> = dict
            .get("ProgramArguments")
            .and_then(plist::Value::as_array)
            .expect("args")
            .iter()
            .filter_map(plist::Value::as_string)
            .collect();
        assert_eq!(args, [exe.to_str().expect("utf8"), "report", "--notify"]);
        let mut xml = Vec::new();
        value.to_writer_xml(&mut xml).expect("xml");
        let text = String::from_utf8(xml).expect("utf8");
        assert!(text.contains("disk &amp; dust.app"), "paths are XML-escaped");
        assert_eq!(plist::Value::from_reader_xml(text.as_bytes()).expect("round trip"), value);
    }

    #[test]
    fn systemd_units_quote_the_executable() {
        let (service, timer) = systemd_units(Path::new("/opt/my apps/50% \"x\"/diskdust"));
        assert!(service.contains(r#"ExecStart="/opt/my apps/50%% \"x\"/diskdust" report --notify"#), "{service}");
        assert!(timer.contains("OnCalendar=Mon *-*-* 10:00:00") && timer.contains("WantedBy=timers.target"));
    }

    #[test]
    fn install_and_remove_on_both_platforms() {
        for os in [Os::MacOs, Os::Linux] {
            let home = tempfile::tempdir().expect("tempdir");
            let runner = Recorder::default();
            assert!(!is_installed(os, home.path()));
            install(os, home.path(), Path::new("/usr/bin/diskdust"), &runner).expect("install");
            assert!(is_installed(os, home.path()), "{os:?}");
            remove(os, home.path(), &runner).expect("remove");
            assert!(!is_installed(os, home.path()));
            assert!(files(os, home.path()).iter().all(|f| !f.exists()));
            let calls = runner.calls.lock().expect("lock").clone();
            let expected: &[&str] = match os {
                Os::MacOs => &["launchctl bootout", "launchctl bootstrap gui/", "launchctl bootout"],
                Os::Linux => &[
                    "systemctl --user daemon-reload",
                    "systemctl --user enable --now diskdust-report.timer",
                    "systemctl --user disable --now diskdust-report.timer",
                    "systemctl --user daemon-reload",
                ],
            };
            assert_eq!(calls.len(), expected.len(), "{calls:?}");
            for (call, prefix) in calls.iter().zip(expected) {
                assert!(call.starts_with(prefix), "{call} vs {prefix}");
            }
        }
    }

    #[test]
    fn activation_failure_is_reported() {
        let home = tempfile::tempdir().expect("tempdir");
        let runner = Recorder { fail: Some("enable"), ..Recorder::default() };
        let err = install(Os::Linux, home.path(), Path::new("/usr/bin/diskdust"), &runner).unwrap_err();
        assert!(err.contains("enable") && err.contains("boom"), "{err}");
        assert!(!is_installed(Os::Linux, home.path()), "nothing is left behind when activation fails");
        assert!(files(Os::Linux, home.path()).iter().all(|f| !f.exists()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_agent_passes_plutil_lint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.plist");
        launch_agent(Path::new("/Applications/diskdust.app/Contents/MacOS/diskdust"))
            .to_file_xml(&path)
            .expect("write");
        let out = std::process::Command::new("/usr/bin/plutil").arg("-lint").arg(&path).output().expect("plutil");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    }
}
