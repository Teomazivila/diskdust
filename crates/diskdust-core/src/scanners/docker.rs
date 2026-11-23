//! Docker images, containers, volumes and build cache via `docker system df`.

use std::time::Duration;

use serde::Deserialize;

use super::{MIN_BYTES, ScanContext, ScanError, Scanner, base_finding};
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
        let mut aggregates = parse_df(&out.stdout);
        // Per-item rows replace the all-or-nothing prunes for images and volumes when available.
        if let Some(items) = verbose_items(ctx) {
            aggregates.retain(|f| f.id != "docker:Images" && f.id != "docker:Local Volumes");
            found.extend(items);
        }
        found.extend(aggregates);
        Ok(found)
    }
}

/// `docker system df -v --format '{{json .}}'`: one JSON object with per-item arrays.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct Verbose {
    images: Vec<ImageRow>,
    volumes: Vec<VolumeRow>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct ImageRow {
    #[serde(rename = "ID")]
    id: String,
    repository: String,
    tag: String,
    containers: String,
    created_at: String,
    unique_size: String,
    shared_size: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct VolumeRow {
    name: String,
    links: String,
    size: String,
}

fn verbose_items(ctx: &ScanContext<'_>) -> Option<Vec<Finding>> {
    let argv: Vec<String> =
        ["docker", "system", "df", "-v", "--format", "{{json .}}"].iter().map(|s| (*s).to_owned()).collect();
    let out = ctx.runner.run(&argv, Duration::from_secs(60)).ok().filter(|o| o.success)?;
    parse_verbose(&out.stdout)
}

/// Unused images and volumes as individual findings; `None` when the output is not understood.
fn parse_verbose(stdout: &str) -> Option<Vec<Finding>> {
    let verbose: Verbose = serde_json::from_str(stdout.trim()).ok()?;
    let images = verbose.images.into_iter().filter(|i| i.containers == "0").filter_map(|i| {
        let cmd = KnownCommand::DockerRemoveImage { id: i.id.clone() };
        if !cmd.is_well_formed() {
            return None;
        }
        let bytes = parse_docker_size(&i.unique_size)?;
        let short = i.id.trim_start_matches("sha256:").chars().take(12).collect::<String>();
        let title = if i.repository == "<none>" {
            format!("Untagged image {short}")
        } else {
            format!("Image {}:{}", i.repository, i.tag)
        };
        let shared = parse_docker_size(&i.shared_size).unwrap_or(0);
        let mut detail = "Docker image not used by any container. Removed with `docker image rm`; pull or build it \
                          again if you need it."
            .to_owned();
        if shared > 0 {
            detail.push_str(" Layers shared with other images stay.");
        }
        Some(Finding {
            detail,
            bytes: Some(bytes),
            last_modified: parse_docker_time(&i.created_at),
            action: Some(CleanupAction::Run(cmd)),
            specificity: SPECIFIC,
            ..base_finding("docker", format!("docker:image:{}", i.id), Category::Containers, title)
        })
    });
    let volumes = verbose.volumes.into_iter().filter(|v| v.links == "0").filter_map(|v| {
        let cmd = KnownCommand::DockerRemoveVolume { name: v.name.clone() };
        if !cmd.is_well_formed() {
            return None;
        }
        let bytes = parse_docker_size(&v.size)?;
        let anonymous = v.name.len() == 64 && v.name.bytes().all(|b| b.is_ascii_hexdigit());
        let title =
            if anonymous { format!("Anonymous volume {}", &v.name[..12]) } else { format!("Volume {}", v.name) };
        Some(Finding {
            detail: "Docker volume not attached to any container. Volumes can hold database data; removed with \
                     `docker volume rm`."
                .to_owned(),
            bytes: Some(bytes),
            action: Some(CleanupAction::Run(cmd)),
            specificity: SPECIFIC,
            ..base_finding("docker", format!("docker:volume:{}", v.name), Category::Containers, title)
        })
    });
    // Same threshold as every other scanner: tiny volumes would only clutter the list.
    Some(images.chain(volumes).filter(|f| f.bytes.is_some_and(|b| b >= MIN_BYTES)).collect())
}

/// Parses Docker's `2026-11-12 20:24:30 +0000 WET` into Unix seconds.
fn parse_docker_time(text: &str) -> Option<i64> {
    let mut parts = text.split_whitespace();
    let (date, clock, offset) = (parts.next()?, parts.next()?, parts.next()?);
    let mut d = date.split('-').map(str::parse::<i32>);
    let (year, month, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut c = clock.split(':').map(str::parse::<u8>);
    let (hour, minute, second) = (c.next()?.ok()?, c.next()?.ok()?, c.next()?.ok()?);
    let sign: i8 = match offset.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let digits = offset.get(1..5)?;
    let (oh, om): (i8, i8) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
    let date = time::Date::from_calendar_date(
        year,
        time::Month::try_from(u8::try_from(month).ok()?).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()?;
    let clock = time::Time::from_hms(hour, minute, second).ok()?;
    let offset = time::UtcOffset::from_hms(sign * oh, sign * om, 0).ok()?;
    Some(time::PrimitiveDateTime::new(date, clock).assume_offset(offset).unix_timestamp())
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

    const DF_V: &str = "docker system df -v --format {{json .}}";

    fn image_id(fill: &str) -> String {
        format!("sha256:{}", fill.repeat(64 / fill.len()))
    }

    /// Same shape as `docker system df -v --format '{{json .}}'` from Docker 29.9 (synthetic data).
    fn verbose_fixture() -> String {
        format!(
            r#"{{"Images":[
            {{"Containers":"0","CreatedAt":"2026-11-12 20:24:30 +0000 WET","ID":"{a}","Repository":"postgres","Tag":"17","SharedSize":"10MB","Size":"415MB","UniqueSize":"405MB"}},
            {{"Containers":"0","CreatedAt":"2025-01-19 12:01:54 +0100 WEST","ID":"{b}","Repository":"<none>","Tag":"<none>","SharedSize":"0B","Size":"2GB","UniqueSize":"2GB"}},
            {{"Containers":"1","CreatedAt":"2026-11-06 22:17:42 +0000 WET","ID":"{c}","Repository":"app","Tag":"local","SharedSize":"0B","Size":"365MB","UniqueSize":"225MB"}},
            {{"Containers":"0","CreatedAt":"bad","ID":"not-an-id","Repository":"evil","Tag":"x","SharedSize":"0B","Size":"1GB","UniqueSize":"1GB"}}
            ],
            "Volumes":[
            {{"Links":"0","Name":"pg_data","Size":"332.8MB"}},
            {{"Links":"0","Name":"{anon}","Size":"1.5GB"}},
            {{"Links":"1","Name":"in_use","Size":"9GB"}},
            {{"Links":"0","Name":"empty","Size":"0B"}},
            {{"Links":"0","Name":"tiny","Size":"86.8kB"}}
            ],
            "Containers":[],"BuildCache":[]}}"#,
            a = image_id("a"),
            b = image_id("b"),
            c = image_id("c"),
            anon = "f".repeat(64)
        )
    }

    #[test]
    fn unused_images_and_volumes_are_listed_individually() {
        let env = Env::new();
        let runner = FakeRunner::new().respond(DF, true, REAL_OUTPUT).respond(DF_V, true, &verbose_fixture());
        let found = DockerScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
        let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Image postgres:17",
                "Untagged image bbbbbbbbbbbb",
                "Volume pg_data",
                "Anonymous volume ffffffffffff",
                "Docker build cache",
            ],
            "used items, invalid ids, empty volumes and the image/volume aggregates are gone"
        );
        assert_eq!(found[0].bytes, Some(405_000_000), "unique size: what removing it frees");
        assert!(found[0].detail.contains("shared with other images"));
        assert_eq!(found[0].last_modified, Some(1_794_515_070));
        assert_eq!(found[1].last_modified, Some(1_737_284_514), "offset +0100 applied");
        assert_eq!(found[0].action, Some(CleanupAction::Run(KnownCommand::DockerRemoveImage { id: image_id("a") })));
        assert_eq!(
            found[2].action,
            Some(CleanupAction::Run(KnownCommand::DockerRemoveVolume { name: "pg_data".into() }))
        );
        assert!(found.iter().take(4).all(|f| f.risk == Risk::Review));
    }

    #[test]
    fn falls_back_to_prunes_without_verbose_output() {
        let env = Env::new();
        for runner in [
            FakeRunner::new().respond(DF, true, REAL_OUTPUT).respond(DF_V, false, ""),
            FakeRunner::new().respond(DF, true, REAL_OUTPUT).respond(DF_V, true, "not json"),
        ] {
            let found = DockerScanner.scan(&env.ctx(Os::Linux, &runner)).expect("scan");
            let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
            assert_eq!(titles, ["Unused Docker images", "Unused Docker volumes", "Docker build cache"]);
        }
    }

    #[test]
    fn docker_timestamps() {
        assert_eq!(parse_docker_time("2026-11-12 20:24:30 +0000 WET"), Some(1_794_515_070));
        assert_eq!(parse_docker_time("2026-11-12 20:24:30 -0130 X"), Some(1_794_520_470));
        for bad in
            ["", "2026-11-12", "2026-13-12 20:24:30 +0000", "2026-11-12 25:00:00 +0000", "2026-11-12 20:24:30 0000"]
        {
            assert_eq!(parse_docker_time(bad), None, "{bad:?}");
        }
    }
}
