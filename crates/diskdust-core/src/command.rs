//! External command execution behind a trait, so scanners can be tested with canned output.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("`{0}` is not installed or not on PATH")]
    NotFound(String),
    #[error("empty command")]
    Empty,
    #[error("failed to start `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{program}` did not finish within {timeout:?}")]
    TimedOut { program: String, timeout: Duration },
}

/// Runs external programs.
pub trait CommandRunner: Send + Sync {
    /// Runs `argv` (element 0 is the program) and captures its output.
    fn run(&self, argv: &[String], timeout: Duration) -> Result<CommandOutput, CommandError>;
    /// Whether `program` can be found.
    fn exists(&self, program: &str) -> bool;
}

/// Runner backed by real processes.
///
/// GUI apps launched from Finder or a desktop launcher inherit a minimal `PATH`, so well-known
/// tool locations (Homebrew, Docker Desktop, snap, Go) are appended to the search path.
#[derive(Debug, Clone)]
pub struct SystemRunner {
    search_path: Vec<PathBuf>,
    /// Start children with an empty environment (plus `PATH` and `LC_ALL`).
    clear_env: bool,
}

/// Root-owned system program directories, the only ones the privileged helper searches.
const TRUSTED_PATH: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

impl SystemRunner {
    pub fn new(home: &Path) -> Self {
        let mut search_path: Vec<PathBuf> =
            std::env::var_os("PATH").map_or_default(|p| std::env::split_paths(&p).collect());
        let extras = [
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/opt/homebrew/sbin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/sbin"),
            PathBuf::from("/usr/local/go/bin"),
            PathBuf::from("/home/linuxbrew/.linuxbrew/bin"),
            PathBuf::from("/snap/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/sbin"),
            home.join(".docker/bin"),
            home.join(".orbstack/bin"),
            home.join("go/bin"),
        ];
        for extra in extras {
            if !search_path.contains(&extra) {
                search_path.push(extra);
            }
        }
        Self { search_path, clear_env: false }
    }

    /// Runner for the privileged helper: resolves programs only in root-owned system directories,
    /// ignores the inherited `PATH`, and starts children with a cleared environment, so nothing
    /// in a user-writable location (Homebrew, linuxbrew, `~/go/bin`) can run as root.
    pub fn trusted() -> Self {
        Self { search_path: TRUSTED_PATH.iter().map(PathBuf::from).collect(), clear_env: true }
    }

    fn resolve(&self, program: &str) -> Option<PathBuf> {
        if program.contains('/') {
            let p = PathBuf::from(program);
            return p.is_file().then_some(p);
        }
        self.search_path.iter().map(|dir| dir.join(program)).find(|candidate| candidate.is_file())
    }

    fn joined_path(&self) -> OsString {
        std::env::join_paths(&self.search_path).unwrap_or_default()
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, argv: &[String], timeout: Duration) -> Result<CommandOutput, CommandError> {
        let (program, rest) = argv.split_first().ok_or(CommandError::Empty)?;
        let resolved = self.resolve(program).ok_or_else(|| CommandError::NotFound(program.clone()))?;
        let mut command = Command::new(&resolved);
        if self.clear_env {
            command.env_clear();
        }
        let child = command
            .args(rest)
            .env("PATH", self.joined_path())
            .env("HOMEBREW_NO_AUTO_UPDATE", "1")
            .env("HOMEBREW_NO_ENV_HINTS", "1")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| CommandError::Spawn { program: program.clone(), source })?;
        wait_with_timeout(child, program, timeout)
    }

    fn exists(&self, program: &str) -> bool {
        self.resolve(program).is_some()
    }
}

fn wait_with_timeout(mut child: Child, program: &str, timeout: Duration) -> Result<CommandOutput, CommandError> {
    let stdout = child.stdout.take().map(spawn_reader);
    let stderr = child.stderr.take().map(spawn_reader);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandError::TimedOut { program: program.to_owned(), timeout });
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(source) => return Err(CommandError::Spawn { program: program.to_owned(), source }),
        }
    };
    let collect = |h: Option<thread::JoinHandle<String>>| h.and_then(|h| h.join().ok()).unwrap_or_default();
    Ok(CommandOutput {
        success: status.success(),
        code: status.code(),
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

fn spawn_reader<R: Read + Send + 'static>(mut source: R) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = source.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

#[cfg(test)]
pub(crate) mod fake {
    //! Scripted runner for scanner tests.
    use super::{CommandError, CommandOutput, CommandRunner};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Debug, Default)]
    pub struct FakeRunner {
        responses: HashMap<String, CommandOutput>,
        installed: Vec<String>,
        pub calls: Mutex<Vec<String>>,
    }

    impl FakeRunner {
        pub fn new() -> Self {
            Self::default()
        }

        /// Registers `program` as installed and scripts the output for the exact command line.
        /// Like [`Self::respond`] with an explicit exit code (0 = success).
        pub fn respond_code(self, cmdline: &str, code: i32, stdout: &str) -> Self {
            let mut runner = self.respond(cmdline, code == 0, stdout);
            if let Some(out) = runner.responses.get_mut(cmdline) {
                out.code = Some(code);
            }
            runner
        }

        pub fn respond(mut self, cmdline: &str, success: bool, stdout: &str) -> Self {
            let program = cmdline.split_whitespace().next().unwrap_or_default().to_owned();
            if !self.installed.contains(&program) {
                self.installed.push(program);
            }
            self.responses.insert(
                cmdline.to_owned(),
                CommandOutput {
                    success,
                    code: Some(i32::from(!success)),
                    stdout: stdout.into(),
                    stderr: String::new(),
                },
            );
            self
        }

        pub fn installed(mut self, program: &str) -> Self {
            self.installed.push(program.to_owned());
            self
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[String], _timeout: Duration) -> Result<CommandOutput, CommandError> {
            let line = argv.join(" ");
            self.calls.lock().expect("lock").push(line.clone());
            let program = argv.first().ok_or(CommandError::Empty)?;
            if !self.exists(program) {
                return Err(CommandError::NotFound(program.clone()));
            }
            Ok(self.responses.get(&line).cloned().unwrap_or(CommandOutput {
                success: true,
                code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            }))
        }

        fn exists(&self, program: &str) -> bool {
            self.installed.iter().any(|p| p == program)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> SystemRunner {
        SystemRunner::new(Path::new("/nonexistent-home"))
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn captures_stdout_and_status() {
        let out =
            runner().run(&argv(&["sh", "-c", "echo hi; echo err >&2; exit 3"]), Duration::from_secs(5)).expect("run");
        assert!(!out.success);
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout.trim(), "hi");
        assert_eq!(out.stderr.trim(), "err");
    }

    #[test]
    fn missing_program_is_not_found() {
        let err = runner().run(&argv(&["diskdust-no-such-tool"]), Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, CommandError::NotFound(_)));
        assert!(!runner().exists("diskdust-no-such-tool"));
        assert!(runner().exists("sh"));
        assert!(runner().exists("/bin/sh"));
        assert!(!runner().exists("/bin/diskdust-no-such-tool"));
    }

    #[test]
    fn trusted_runner_uses_only_system_dirs_and_a_clean_env() {
        let trusted = SystemRunner::trusted();
        assert_eq!(trusted.search_path, TRUSTED_PATH.iter().map(PathBuf::from).collect::<Vec<_>>());
        assert!(trusted.exists("sh"));
        assert!(!trusted.exists("diskdust-no-such-tool"));
        // HOME is set for the test process; the cleared child environment must not see it.
        let out =
            trusted.run(&argv(&["sh", "-c", "echo \"$HOME|$PATH|$LC_ALL\""]), Duration::from_secs(5)).expect("run");
        assert_eq!(out.stdout.trim(), "|/usr/bin:/bin:/usr/sbin:/sbin|C");
        assert!(!runner().clear_env);
    }

    #[test]
    fn empty_argv_is_rejected() {
        assert!(matches!(runner().run(&[], Duration::from_secs(1)), Err(CommandError::Empty)));
    }

    #[test]
    fn times_out_and_kills() {
        let start = Instant::now();
        let err = runner().run(&argv(&["sleep", "5"]), Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, CommandError::TimedOut { .. }));
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn large_output_does_not_deadlock() {
        let out = runner().run(&argv(&["sh", "-c", "yes x | head -c 2000000"]), Duration::from_secs(10)).expect("run");
        assert_eq!(out.stdout.len(), 2_000_000);
    }
}
