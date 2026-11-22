//! Docker images, containers, volumes and build cache via `docker system df`.

use std::time::Duration;

use serde::Deserialize;

use super::{ScanContext, ScanError, Scanner, base_finding};
use crate::model::{Category, CleanupAction, Finding, KnownCommand, Os, Risk, SPECIFIC};
use crate::size::allocated_bytes;
use crate::units::parse_docker_size;

/// Relative location of Docker Desktop's VM disk on macOS.
const DOCKER_RAW: &str = "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw";

#[derive(Debug)]
pub struct DockerScanner;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DfRow {
    #[serde(rename = "Type")]
    kind: String,
    reclaimable: String,
    total_count: String,
    active: String,
}

impl Scanner for DockerScanner {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn name(&self) -> &'static str {
        "Docker"
    }

    fn supports(&self, _os: Os) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, ScanError> {
        let mut found = Vec::new();
        if ctx.os == Os::MacOs {
            found.extend(docker_raw(ctx));
        }
        if !ctx.runner.exists("docker") {
            return Ok(found);
        }
        let argv: Vec<String> =
            ["docker", "system", "df", "--format", "{{json .}}"].iter().map(|s| (*s).to_owned()).collect();
        let out = ctx.runner.run(&argv, Duration::from_secs(30))?;
        if !out.success {
            return Err(ScanError::Unavailable(
                "Docker is installed but the daemon is not reachable (is Docker running?)".to_owned(),
            ));
        }
        found.extend(parse_df(&out.stdout));
        Ok(found)
    }
}

fn parse_df(stdout: &str) -> Vec<Finding> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<DfRow>(line.trim()).ok())
        .filter_map(|row| {
            let bytes = parse_docker_size(&row.reclaimable)?;
            if bytes == 0 {
                return None;
            }
            let (title, detail, risk, cmd) = match row.kind.as_str() {
                "Images" => (
                    "Unused Docker images",
                    format!(
                        "{} images, {} in use. Removes every image not used by a container; they are re-pulled or rebuilt when needed.",
                        row.total_count, row.active
                    ),
                    Risk::Review,
                    KnownCommand::DockerPruneImages,
                ),
                "Containers" => (
                    "Stopped Docker containers",
                    format!("{} containers, {} running. Removes stopped containers and their writable layers.", row.total_count, row.active),
                    Risk::Review,
                    KnownCommand::DockerPruneContainers,
                ),
                "Local Volumes" => (
                    "Unused Docker volumes",
                    format!(
                        "{} volumes, {} in use. Volumes can hold database data; removes every volume not attached to a container.",
                        row.total_count, row.active
                    ),
                    Risk::Review,
                    KnownCommand::DockerPruneVolumes,
                ),
                "Build Cache" => (
                    "Docker build cache",
                    format!("{} cache records. Builds will be slower the first time afterwards.", row.total_count),
                    Risk::Safe,
                    KnownCommand::DockerPruneBuildCache,
                ),
                _ => return None,
            };
            Some(Finding {
                detail,
                bytes: Some(bytes),
                risk,
                action: Some(CleanupAction::Run(cmd)),
                specificity: SPECIFIC,
                ..base_finding("docker", format!("docker:{}", row.kind), Category::Containers, title.to_owned())
            })
        })
        .collect()
}

fn docker_raw(ctx: &ScanContext<'_>) -> Option<Finding> {
    let path = ctx.home.join(DOCKER_RAW);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some(Finding {
        detail: "Docker Desktop's virtual disk (info only). Pruning frees space inside it and Docker Desktop \
                 returns it to macOS over time; lower the limit in Docker Desktop → Settings → Resources."
            .to_owned(),
        path: Some(path),
        bytes: Some(allocated_bytes(&meta)),
        specificity: SPECIFIC,
        ..base_finding("docker", "docker:raw".to_owned(), Category::Containers, "Docker Desktop disk image".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::fake::FakeRunner;
    use crate::scanners::testutil::{BIG, Env};

    /// Captured from Docker Desktop 29.9.3.
    const REAL_OUTPUT: &str = r#"{"Active":"2","Reclaimable":"31.3GB (88%)","Size":"35.43GB","TotalCount":"49","Type":"Images"}
{"Active":"2","Reclaimable":"0B (0%)","Size":"49.15kB","TotalCount":"2","Type":"Containers"}
{"Active":"2","Reclaimable":"4.408GB (98%)","Size":"4.473GB","TotalCount":"27","Type":"Local Volumes"}
{"Active":"0","Reclaimable":"12.85GB","Size":"26.48GB","TotalCount":"185","Type":"Build Cache"}
"#;
    const DF: &str = "docker system df --format {{json .}}";

    #[test]
    fn parses_real_output() {
        let env = Env::new();
        let runner = FakeRunner::new().respond(DF, true, REAL_OUTPUT);
        let found = DockerScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        let summary: Vec<_> = found.iter().map(|f| (f.title.as_str(), f.bytes, f.risk)).collect();
        assert_eq!(
            summary,
            [
                ("Unused Docker images", Some(31_300_000_000), Risk::Review),
                ("Unused Docker volumes", Some(4_408_000_000), Risk::Review),
                ("Docker build cache", Some(12_850_000_000), Risk::Safe),
            ]
        );
        assert_eq!(found[1].action, Some(CleanupAction::Run(KnownCommand::DockerPruneVolumes)));
        assert!(found[0].detail.contains("49 images"));
    }

    #[test]
    fn stopped_containers_reported() {
        let line = r#"{"Active":"1","Reclaimable":"2GB (50%)","Size":"4GB","TotalCount":"3","Type":"Containers"}"#;
        let found = parse_df(line);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::DockerPruneContainers)));
    }

    #[test]
    fn ignores_unknown_rows_and_garbage() {
        let input = "not json\n{\"Active\":\"0\",\"Reclaimable\":\"1GB\",\"Size\":\"1GB\",\"TotalCount\":\"1\",\"Type\":\"Other\"}\n";
        assert!(parse_df(input).is_empty());
    }

    #[test]
    fn not_installed_yields_nothing() {
        let env = Env::new();
        let runner = FakeRunner::new();
        assert!(DockerScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
    }

    #[test]
    fn daemon_down_is_reported() {
        let env = Env::new();
        let runner = FakeRunner::new().respond(DF, false, "");
        let err = DockerScanner.scan(&env.ctx(Os::Linux, &runner)).unwrap_err();
        assert!(err.to_string().contains("not reachable"));
    }

    #[test]
    fn docker_raw_is_informational_on_mac() {
        let env = Env::new();
        env.file(DOCKER_RAW, BIG);
        let runner = FakeRunner::new();
        let found = DockerScanner.scan(&env.ctx(Os::MacOs, &runner)).expect("scan");
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_actionable());
        assert!(found[0].bytes.expect("bytes") >= BIG as u64);
        assert!(DockerScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan").is_empty());
        assert_eq!(DockerScanner.id(), "docker");
        assert!(DockerScanner.supports(Os::MacOs));
    }
}
