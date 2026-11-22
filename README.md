# diskdust

A native desktop app (and read-only CLI) that finds **non-obvious reclaimable disk space** on macOS
and Linux — container data, `~/Library`, developer caches, build artifacts, system caches — shows it
grouped by category and size, and reclaims it safely.

Written in Rust (`eframe`/`egui`), one binary, no runtime dependencies.

## What it finds

| Category | macOS | Linux |
|---|---|---|
| Containers | Unused Docker images, stopped containers, unused volumes, build cache (`docker system df`); `Docker.raw` (info) | same |
| App caches | `~/Library/Caches/*`, Slack / VS Code / Cursor / Discord / Chrome caches | `~/.cache/*`, Slack / VS Code / Discord / Chrome under `~/.config` |
| Logs | `~/Library/Logs/*`, `/Library/Logs/*` 🔒 | systemd journal (`journalctl --vacuum-time=7d`) 🔒 |
| Developer caches | Cargo, npm, pnpm, Yarn, Bun, pip, uv, Gradle, Maven, Helm, Deno, Playwright, CocoaPods, JetBrains, Terraform, minikube, Hugging Face, Ollama, Homebrew (`brew cleanup`), Go (`go clean`) | same (XDG paths) |
| Build artifacts | `target/`, `node_modules/`, `.next/`, `.terraform/`, `.venv/`, Gradle `build/` and `.gradle/` under your project folders | same |
| Xcode | DerivedData, Archives, device support, simulator caches, unavailable simulators | — |
| Device backups | iPhone/iPad backups | — |
| Orphaned app data | `~/Library/Application Support/<bundle-id>` with no installed app | — |
| Trash | `~/.Trash` | `~/.local/share/Trash` |
| System 🔒 | `/Library/Caches/*`, Time Machine local snapshots | APT, DNF, DNF5, pacman caches; disabled snap revisions |

🔒 = needs your administrator password when cleaned.

Every item is marked **Safe** (rebuildable cache) or **Review** (may hold data you want — never
pre-selected by *Select safe*). Items that can only be explained, not cleaned (e.g. Docker Desktop's
disk image), are marked **Info**.

Sizes are **allocated** bytes (real disk usage). Files hard-linked from elsewhere — e.g. a
`node_modules` installed by pnpm — are not counted as reclaimable, because removing one link does
not free them; the item says how much is shared.

## Safety model

- **Scanning is read-only.** Nothing is removed until you select items and confirm.
- **Move to Trash** is the default; *Delete permanently* is a per-clean toggle. The confirmation
  dialog names every item that is removed permanently regardless of mode (emptying the Trash, tool
  commands such as `docker image prune`, admin items).
- **Every path is validated twice** — when scanned and again immediately before removal: it must be
  absolute, exist, not be a symlink, lie strictly inside its declared root after resolving
  symlinks, and must not be (or contain) a protected location (`/`, `$HOME`, `/System`, `/usr`,
  `~/Documents`, `~/.ssh`, …). Walks never follow symlinks or cross file systems.
- **No arbitrary commands.** External tools run from a closed list of fixed argument vectors.
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
diskdust               # open the desktop app
diskdust scan          # read-only report in the terminal
diskdust scan --json   # same, as JSON
```

### macOS privacy prompts

diskdust searches common project folders (`~/Documents`, `~/code`, `~/Projects`, …) for build
output. Because `~/Documents` is protected, macOS asks once whether diskdust may access it; remove
the folder under **Project folders** to skip it. The Trash and some app data are unreadable without
*Full Disk Access*; diskdust then reports their size as unknown and, for the Trash, asks Finder to
empty it.

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

## Development

```
crates/diskdust-core   engine: scanners, size walker, safety, cleaner, audit log, privilege helper
crates/diskdust        binary: egui UI, background workers, CLI, `helper` subcommand
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
