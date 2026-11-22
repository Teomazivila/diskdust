# diskdust — Design & Implementation Plan

> Status: v1 implemented 2026-11-22 (see §9) · Toolchain: Rust 1.100.0, edition 2024 · Targets: macOS, Linux

## 1. Goal

A fast, native desktop app that finds non-obvious reclaimable disk space on macOS and Linux
laptops (container data, `~/Library`, developer caches, build artifacts, system caches), shows it
grouped by category and size, and lets the user reclaim it safely.

## 2. Decisions

| Topic | Decision | Rationale |
|---|---|---|
| UI toolkit | `eframe`/`egui` 0.37 | Pure Rust, single binary, instant startup, fastest route to a polished cross-platform tool. iced 0.14 is still pre-1.0; Slint's GPL/commercial licensing adds friction; Tauri needs a web frontend. |
| Directory walking | Own walker on `rayon` | `jwalk` is deprecated upstream ("use dua-core"); our needs (allocated size, no symlink following, no mount crossing, hardlink dedupe, cancellation) fit in a small, fully tested module. |
| Docker integration | `docker` CLI, not the Engine API | Automatically honours the active context (Docker Desktop, Colima, OrbStack) and avoids pulling in an async runtime. Output formats verified against Docker 29.9. |
| Podman | Out of scope for v1 | Not installed on the dev machine; output format could not be verified (zero-guesswork rule). |
| Delete behaviour | Move to Trash by default, permanent delete is a per-clean toggle | Recoverability first. UI states clearly that trashed bytes are reclaimed only when the Trash is emptied. |
| Privilege model | App always runs as the user. Admin items are opt-in and executed by `diskdust helper` via the OS-native prompt (`osascript … with administrator privileges` on macOS, `pkexec` on Linux) | Never run a GUI as root. The helper receives a hex-encoded, typed action list (no shell strings), and re-validates every action against a hard-coded admin allowlist. |
| Size metric | Allocated blocks (`st_blocks * 512`) | Reports real disk usage (sparse files such as `Docker.raw`, APFS). |

## 3. Architecture

```
diskdust/                     (Cargo workspace)
├── crates/diskdust-core      library: all logic, ≥80% test coverage
│   ├── model.rs              Finding, Category, Risk, Privilege, CleanupAction, KnownCommand
│   ├── size.rs               parallel allocated-size walker
│   ├── safety.rs             path validation (protected paths, allowed roots, symlinks)
│   ├── command.rs            CommandRunner trait + real runner with timeout
│   ├── units.rs              Docker/journalctl size parsing, human formatting
│   ├── scan.rs               scan orchestration, progress events, overlap dedupe
│   ├── scanners/             path rules table + Docker, Homebrew, Go, Trash, Time Machine,
│   │                         journald, apt/dnf/pacman, snap, flatpak, orphaned app data,
│   │                         build artifacts
│   ├── clean.rs              executor (trash / permanent / known commands)
│   ├── audit.rs              JSONL deletion log
│   └── privilege.rs          helper payload encoding + elevation command construction
└── crates/diskdust           binary: egui UI + `helper` subcommand
```

### Data model

- `Finding { id, scanner, category, title, detail, path, bytes: Option<u64>, risk, privilege, action: Option<CleanupAction> }`
  - `action == None` → informational only (e.g. `Docker.raw`).
  - `bytes == None` → size cannot be determined (e.g. Time Machine snapshots).
- `Risk::Safe` (rebuildable cache) / `Risk::Review` (may hold real data — never pre-selected).
- `CleanupAction::RemovePath { path, root }`, `EmptyDir { path, root }`, `Run(KnownCommand)`.
- `KnownCommand` is a closed enum mapped to fixed argv vectors — no free-form commands exist.

### Safety rules (enforced at scan time and again at clean time)

1. Paths must be absolute and exist; the target itself must not be a symlink.
2. Canonical path must be strictly inside its declared allowed root.
3. Target must not equal, or be an ancestor of, any protected path (`/`, `$HOME`, `/System`,
   `/usr`, `/bin`, `/etc`, `/Library`, `/Applications`, user content folders, …).
4. Walks never follow symlinks and never cross filesystem boundaries.
5. Helper ignores the root sent by the app and validates against its own fixed admin roots.

## 4. Scanner catalogue (v1)

| Category | macOS | Linux | Privilege |
|---|---|---|---|
| Containers | Docker images / stopped containers / unused volumes / build cache (via `docker system df`), `Docker.raw` (info) | same Docker items | user |
| App caches | `~/Library/Caches/*`, Slack/VS Code/Cursor/Discord caches | `~/.cache/*` | user |
| Logs | `~/Library/Logs/*`, `/Library/Logs/*` 🔒 | journald (`journalctl --vacuum-time=7d`) 🔒 | mixed |
| Developer caches | Cargo, npm, pnpm, Yarn Berry, Bun, Gradle, Maven, pip, uv, Go (`go clean`), Hugging Face, Ollama, Terraform, Helm, Deno, minikube, Homebrew (`brew cleanup --prune=all`) | same (XDG paths) | user |
| Build artifacts | `target/` (Cargo), `node_modules/`, `.next/`, `.terraform/`, `.venv/` under configurable project roots | same | user |
| Xcode | DerivedData, Archives, DeviceSupport, CoreSimulator caches, `simctl delete unavailable` | — | user |
| Backups | iOS backups (`MobileSync/Backup/*`) | — | user |
| Orphaned app data | `~/Library/Application Support/<bundle-id>` with no installed app | — | user |
| Trash | `~/.Trash` (Finder empty-trash fallback when unreadable) | `~/.local/share/Trash` | user |
| System | `/Library/Caches/*` 🔒, Time Machine local snapshots 🔒 | apt/dnf/pacman caches 🔒, disabled snap revisions 🔒 | admin |

## 5. UI

- Top bar: Scan / Cancel, Trash ⇄ Permanent toggle, reclaimable total, **Clean selected**.
- Left panel: categories with totals, project-root management.
- Centre: sortable table — checkbox, title, size bar, Safe/Review badge, 🔒, path, reveal.
- Confirmation modal: count, total, mode, warnings for Review and admin items.
- Status bar: live scan progress, last clean summary. Scans and cleans run off the UI thread.

## 6. Quality gates

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings` (pedantic on)
- `cargo test --workspace`
- `cargo llvm-cov -p diskdust-core` ≥ 80% lines
- Core tests also run inside a Linux container (`rust:1.100`) to exercise Linux code paths.
- Manual verification: scan-only run on macOS, then a trash-mode clean of a disposable fixture.

## 7. Out of scope (v1)

Notarised (Developer ID) macOS builds, auto-update, scheduled cleanups, Windows, Podman, Flatpak
(no dry-run to size unused runtimes, so it could not be verified), persisting project folders between launches.

## 8. Implementation steps

1. Workspace scaffold, lint config, dependency pins.
2. Core: model, units, safety, size walker (+ tests).
3. Core: command runner, scanners (+ fixture-based tests with fake home and mocked runner).
4. Core: scan orchestration + overlap dedupe, cleanup executor, audit log, privilege encoding.
5. App: egui UI, background scan/clean workers, elevation, helper subcommand.
6. Gates: fmt, clippy, tests, coverage, Linux container run.
7. Manual verification on macOS.

## 9. Implementation status (2026-11-22)

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` (pedantic) | pass on macOS and Linux |
| Tests | 126 (107 core, 19 app incl. 10 UI tests driving the real app via `egui_kittest`) — pass on macOS and Linux (`rust:1.100-slim`, headless and Mesa-rendered) |
| Coverage (`cargo llvm-cov`) | core 98.5% lines, workspace 93.1% |
| Real scan (macOS) | 64 items, 95 GB reclaimable in 6.4 s |
| Privileged helper (Linux, root) | `apt-get clean` executed; `/etc` path and non-admin command refused |

Deviations from the original plan, with reasons:

- Added a read-only terminal mode, `diskdust scan [--json]`, which reuses the engine (the original ask
  mentioned terminal or desktop; it also enables verification without a display).
- Enabled egui's `monochrome_emoji_fonts` so icons render identically on every OS (UI tests caught
  missing glyphs with the default font set).
- Project roots are de-duplicated by inode (case-insensitive file systems made `~/code` and `~/Code`
  the same folder).
- One clippy pedantic lint is allowed workspace-wide: `assert_is_empty` (test readability).
- UI tests run headless by default (no GPU needed). `DISKDUST_SCREENSHOTS=1 cargo test -p diskdust`
  also renders each screen to `<target dir>/screenshots/*.png`.

Remaining manual checks (need an interactive session on macOS):

1. "Move to Trash" on a real item (uses `NSFileManager`; no Finder automation prompt expected).
2. An admin clean (e.g. `/Library/Logs/DiagnosticReports`) to exercise the macOS password prompt.

### 9.1 Iteration 2 (2026-11-22, after first real use)

- Deep-black theme (`panel_fill` pure black; inputs, striped rows and dialogs on slightly lifted surfaces).
- **Select all** (visible, actionable items; respects the category filter and search).
- Fixed: project-folder remove icon rendered as tofu (`✕` missing from fonts) → `×`, plus a test that every
  UI icon has a glyph.
- Fixed: sidebar/table totals included info-only items (the 64 GB `Docker.raw`); totals now count only
  cleanable bytes and mark unknown sizes ("size unknown", "4.2 GB+").
- Fixed: freed space for Docker prunes now uses Docker's own "Total reclaimed space" (it differed from the
  pre-clean estimate by up to 13.7 GB in real use); the audit log records the same figure.
- App icon (`assets/icon.svg` → PNGs via `resvg`, `assets/icon.icns` via `iconutil`), also used as window icon.

## 10. Installers

Built with `cargo-packager` 0.11.8 (config in `crates/diskdust/Cargo.toml` under
`[package.metadata.packager]`).

| Platform | Command | Output |
|---|---|---|
| macOS | `cargo packager --release --formats app,dmg` | `target/release/diskdust.app`, `target/release/diskdust_<ver>_aarch64.dmg` |
| Linux | `cargo packager --release --formats deb,appimage` | `target/release/diskdust_<ver>_amd64.deb`, `target/release/diskdust_<ver>_x86_64.AppImage` |

- macOS bundles are **ad-hoc signed** (`signing-identity = "-"`, hardened runtime). That is enough to run on the
  machine that built it. To hand the DMG to other people without Gatekeeper warnings, sign with a Developer ID
  and set the `APPLE_*` notarization variables cargo-packager reads.
- Icons are regenerated from `assets/icon.svg` with `resvg` (PNG) and `iconutil` (ICNS); the generated files are
  committed so packaging needs neither tool.
- Verified 2026-11-22: macOS `.app`/`.dmg` (arm64) signature and checksum valid; `.deb` for arm64 and amd64
  installs, runs and uninstalls on Ubuntu 24.04; arm64 AppImage runs. The x86_64 AppImage could not be
  built on this Apple-Silicon machine (`linuxdeploy` aborts under x86 emulation); build it on a native
  x86_64 Linux host with the same command.
