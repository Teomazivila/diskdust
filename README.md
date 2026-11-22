# diskdust

A native desktop app (and CLI) that finds **non-obvious reclaimable disk space** on macOS and Linux —
container data, `~/Library`, developer caches, old toolchains, build artifacts, installers, system
caches — shows it grouped by category, size and age, and reclaims it safely.

Written in Rust (`eframe`/`egui`), one binary, no runtime dependencies.

## Install

Download the file for your system from the
[latest release](https://github.com/Teomazivila/diskdust/releases/latest):

| System | File | How |
|---|---|---|
| macOS, Apple Silicon | `diskdust_<version>_aarch64.dmg` | Open it and drag **diskdust** to Applications |
| macOS, Intel | `diskdust_<version>_x64.dmg` | same |
| Debian / Ubuntu | `diskdust_<version>_amd64.deb` / `_arm64.deb` | `sudo apt install ./diskdust_<version>_amd64.deb` |
| Other Linux | `diskdust_<version>_x86_64.AppImage` / `_aarch64.AppImage` | `chmod +x` it and run it |

The macOS app is signed ad hoc but not notarized yet, so macOS blocks the first launch ("cannot
verify … is free of malware"). Once per version, either open it, click **Done**, then go to
**System Settings → Privacy & Security → Open Anyway**; or run
`xattr -d com.apple.quarantine /Applications/diskdust.app` and open it normally. (Right-click →
**Open** no longer bypasses this check since macOS 15.)

Each release lists `SHA256SUMS` and carries signed build provenance:
`sha256sum -c SHA256SUMS --ignore-missing` and
`gh attestation verify <file> --repo Teomazivila/diskdust`.

For the terminal commands on macOS, link the binary onto your `PATH`, e.g.
`ln -s /Applications/diskdust.app/Contents/MacOS/diskdust ~/.local/bin/diskdust`.

## What it finds

| Category | macOS | Linux |
|---|---|---|
| Containers | Unused Docker images, stopped containers, unused volumes, build cache (`docker system df`); `Docker.raw`, Lima / Colima VM disks (info) | same (Lima / Colima where installed) |
| App caches | `~/Library/Caches/*`, Slack / VS Code / Cursor / Discord / Chrome caches | `~/.cache/*`, Slack / VS Code / Discord / Chrome under `~/.config` |
| Logs | `~/Library/Logs/*`, `/Library/Logs/*` 🔒 | systemd journal (`journalctl --vacuum-time=7d`) 🔒 |
| Developer caches | Cargo, npm, pnpm, Yarn, Bun, pip, uv, Gradle, Maven, Helm, Deno, Playwright, CocoaPods, JetBrains, Terraform, minikube, Hugging Face, Ollama, Homebrew (`brew cleanup`), Go (`go clean`) | same (XDG paths) |
| Old toolchains | rustup toolchains other than default/active, nvm / fnm Node versions other than the default, pyenv versions other than the global one, older JetBrains IDE settings, Android system images | same |
| Build artifacts | `target/`, `node_modules/`, `.next/`, `.terraform/`, `.venv/`, Gradle `build/` and `.gradle/` under your project folders | same |
| Installers | `Install macOS *.app`; `.dmg` / `.pkg` / `.iso` in Downloads untouched for 30+ days | `.iso` / `.deb` / `.rpm` / `.AppImage` in Downloads, 30+ days |
| Xcode | DerivedData, Archives, device support, simulator caches, unavailable simulators | — |
| Device backups | iPhone/iPad backups | — |
| Orphaned app data | `Application Support`, `Saved Application State`, `HTTPStorages`, `WebKit` folders of bundle ids with no installed app | — |
| Trash | `~/.Trash` | `~/.local/share/Trash` |
| System 🔒 | `/Library/Caches/*`, Time Machine local snapshots | APT, DNF, DNF5, pacman caches; disabled snap revisions |

🔒 = needs your administrator password when cleaned.

Every item is marked **Safe** (rebuildable cache) or **Review** (may hold data you want — never
pre-selected by *Select safe*). Items that can only be explained, not cleaned (e.g. Docker Desktop's
disk image), are marked **Info**.

Sizes are **allocated** bytes (real disk usage). Files hard-linked from elsewhere — e.g. a
`node_modules` installed by pnpm — are not counted as reclaimable, because removing one link does
not free them; the item says how much is shared. Every measured item shows when anything inside it
was last modified.

## In the app

- **Filter** by category, name/path, and age (*Untouched 7 / 30 / 90 / 180+ days*).
- **Details panel** (click a row): what cleaning does, the full explanation, and *Largest folders*
  inside the item.
- **Ignore** items for good (row context menu or details panel); *Show ignored* brings them back.
- **Running-app guard**: Slack, VS Code, Cursor, Discord, Chrome caches and Xcode DerivedData are
  skipped while the app runs; the confirmation dialog says which apps to quit.
- **Free space** of your home volume in the toolbar, **Empty Trash** after a Trash-mode clean, and a
  **History** of past cleanups (from the audit log).
- Project folders, delete mode, age filter and ignored items are saved in `settings.json`
  (`~/Library/Application Support/diskdust/` on macOS, `$XDG_CONFIG_HOME/diskdust/` on Linux).

## Safety model

- **Scanning is read-only.** Nothing is removed until you select items and confirm.
- **Move to Trash** is the default; *Delete permanently* is a per-clean toggle. The confirmation
  dialog names every item that is removed permanently regardless of mode (emptying the Trash, tool
  commands such as `docker image prune`, admin items).
- **Every path is validated twice** — when scanned and again immediately before removal: it must be
  absolute, exist, not be a symlink, lie strictly inside its declared root after resolving
  symlinks, and must not be (or contain) a protected location (`/`, `$HOME`, `/System`, `/usr`,
  `~/Documents`, `~/.ssh`, …). Walks never follow symlinks or cross file systems.
- **No arbitrary commands.** External tools run from a closed list of fixed argument vectors;
  arguments derived from scanned data (snap names, rustup toolchain names) are validated.
- **The GUI never runs as root.** Admin items are passed (hex-encoded, typed) to
  `diskdust helper`, launched through the OS prompt (`osascript … with administrator privileges`
  on macOS, `pkexec` on Linux). The helper ignores the folders sent by the app, re-validates every
  item against its own fixed allowlist, and runs tools from root-owned system directories with a
  cleared environment.
- **Audit log.** Every cleanup attempt is appended as JSON Lines, tagged with a per-clean `run_id`:
  `~/Library/Logs/diskdust/cleanup.jsonl` (macOS) or `$XDG_STATE_HOME/diskdust/cleanup.jsonl`
  (Linux, default `~/.local/state`).

## Usage

```sh
diskdust                                   # open the desktop app
diskdust scan [filters] [--json]           # read-only report in the terminal
diskdust clean [filters] --dry-run         # list what would be cleaned
diskdust clean [filters] --yes [--permanent] [--json]
```

Filters: `--category <name>` (repeatable: `containers`, `developer-caches`, `old-toolchains`,
`build-artifacts`, `installers`, `app-caches`, `logs`, `xcode`, `device-backups`,
`orphaned-app-data`, `trash`, `system`), `--safe-only`, `--older-than <days>`.

`diskdust clean` follows the same safety rules as the app: Trash by default, ignored items are never
touched, running apps block their caches, every attempt is audited, and admin items are skipped
(clean those from the app). It exits with status 1 when any item was not cleaned. Example:

```sh
diskdust clean --category build-artifacts --older-than 90 --safe-only --dry-run
```

### macOS privacy prompts

diskdust searches common project folders (`~/Documents`, `~/code`, `~/Projects`, …) for build
output and `~/Downloads` for old installers. Because these folders are protected, macOS asks once
whether diskdust may access them; remove a folder under **Project folders** to skip it. The Trash and
some app data are unreadable without *Full Disk Access*: the app shows a banner with a shortcut to
the setting, reports those sizes as unknown and, for the Trash, asks Finder to empty it.

## Build from source

Requires the toolchain pinned in `rust-toolchain.toml` (Rust **1.100**, installed automatically by
`rustup`). On Linux the window needs `libxkbcommon` (`libxkbcommon0`, `libxkbcommon-x11-0` on
Debian/Ubuntu).

```sh
cargo run --release -p diskdust            # desktop app
cargo run --release -p diskdust -- scan    # terminal report
```

### Installers

Built with [`cargo-packager`](https://github.com/crabnebula-dev/cargo-packager) 0.11.8
(configuration in `crates/diskdust/Cargo.toml`):

| Platform | Command | Output |
|---|---|---|
| macOS | `cargo packager --release --formats app,dmg` | `target/release/diskdust.app`, `diskdust_<ver>_aarch64.dmg` |
| Linux | `cargo packager --release --formats deb,appimage` | `diskdust_<ver>_amd64.deb`, `diskdust_<ver>_x86_64.AppImage` |

macOS bundles are ad-hoc signed; sign with a Developer ID and notarize before distributing them.

### Publishing a release

Releases are built and published by CI (`.github/workflows/release.yml`); tags are never created by
hand.

1. Bump `version` in the workspace `Cargo.toml` in a PR and merge it.
2. Actions → **Release** → *Run workflow* on `main` with that version.

The workflow checks that the version matches `Cargo.toml`, that the tag does not exist and that CI
passed on the commit; builds the `.dmg` (macOS arm64 and Intel) and `.deb` / `.AppImage` (Linux
x86_64 and arm64) on native runners; then creates the `v<version>` tag and the GitHub Release with
`SHA256SUMS` and build provenance. Pull requests that touch packaging run the same builds as a dry
run.

## Development

```
crates/diskdust-core   engine: scanners, size walker, safety, cleaner, audit log, privilege helper,
                       disk space and macOS access probes
crates/diskdust        binary: egui UI, background workers, shared clean session, settings, CLI,
                       `helper` subcommand
```

Quality gates (all run in CI on macOS and Linux, `.github/workflows/ci.yml`):

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings     # clippy::pedantic
cargo test --locked --workspace --no-fail-fast
cargo llvm-cov --locked -p diskdust-core --fail-under-lines 80
cargo audit --deny warnings                                          # ignores documented in deny.toml
cargo deny --locked check
```

- `DISKDUST_SCREENSHOTS=1 cargo test -p diskdust` renders each UI test screen to
  `target/screenshots/*.png`.
- `cargo test -p diskdust-core --lib -- --ignored system_trash` verifies the real platform Trash
  (leaves a small file in your Trash).

Design notes: [`PLAN.md`](PLAN.md). Review findings and roadmap:
[`REMEDIATION_PLAN.md`](REMEDIATION_PLAN.md).

## License

MIT
