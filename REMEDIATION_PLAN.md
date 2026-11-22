# diskdust — Remediation & Feature Plan

> Source: codebase review of `main` @ `6d024fa` (2026-11-22). Toolchain: Rust 1.100.
> Delivery: **PR 1** (`fix/review-remediation`) ships every fix in §2–§3; **PR 2**
> (`feat/usefulness`, stacked on PR 1) ships the features in §4. Status columns are updated in
> the PR that closes each item.

## 1. Baseline (before remediation)

| Gate | Result on `6d024fa` |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | pass on 1.100; **fails to build on 1.98** (`requires rustc 1.100`, no toolchain pin) |
| `cargo test --locked --workspace` | 126 passed |
| `cargo llvm-cov -p diskdust-core` | 98.48 % lines |
| `cargo audit --deny warnings` | **fail** — 4 unmaintained transitive crates |
| `cargo deny check` | **fail** — no `deny.toml` |
| CI | **none** (`.github/` absent) |

## 2. Rule / process gaps (PR 1)

| ID | Gap | Fix | Status |
|---|---|---|---|
| R1 | No toolchain pin; fresh clone on Rust 1.98 does not build | `rust-toolchain.toml` pinned to 1.100 with `rustfmt`, `clippy`, `llvm-tools` | ✅ Done (`920c300`) |
| R2 | No CI; every gate is manual | `.github/workflows/ci.yml`: fmt, clippy (`--locked`, `-D warnings`), tests on macOS + Linux, coverage ≥ 80 % gate, `cargo audit`, `cargo deny`; actions pinned by commit SHA, least-privilege `permissions` | ✅ Done (`e9e219b`) |
| R3 | `cargo audit` fails; no `deny.toml` | `deny.toml` (license allowlist, sources, bans) and `.cargo/audit.toml`. The 4 *unmaintained* advisories (`ttf-parser`, `zbus_names`, `zvariant`, `zvariant_derive`) come from `egui`/`epaint` (fonts) and `accesskit_unix`/`opener` (D-Bus). Every upstream crate is already at its latest release (`cargo update --dry-run`: 0 packages), and removing them would mean dropping accessibility on Linux — so they are ignored with a written justification and re-reviewed on every egui upgrade. No vulnerability advisories exist. | ✅ Done (`920c300`) |
| R4 | Documented gates omit `--locked` | `PLAN.md` §6 and README use `--locked` | ✅ Done (README, PLAN.md) |
| R5 | `d6a0c99` committed directly to `main` | History is not rewritten (no force-push on shared branches). Recommend enabling branch protection on `main` (require PR + CI) — repository setting, owner action | Owner |
| R6 | No property-based tests for parsers and safety rules | `proptest` (dev-dependency) for `units`, `privilege::decode_payload`, `safety` | ✅ Done (`f5605c2`) |
| R7 | Audit entries cannot be grouped per clean run | `run_id` on every `AuditEntry` (backwards-compatible: missing field deserializes as empty) | ✅ Done (`0741a68`) |

## 3. Defects (PR 1)

| ID | Sev. | Defect | Fix | Status |
|---|---|---|---|---|
| B1 | High | Hard-linked files are de-duplicated per measurement only, so pnpm `node_modules` and the pnpm store each report bytes that deleting them alone does not free | Walker counts how many links of each inode lie inside the measured tree; bytes of inodes with links outside are reported as *shared*, not reclaimable. Findings show the shared amount in their detail | ✅ Done (`147d399`) |
| B2 | High | Every `~/Library/Caches/*` child (incl. `com.apple.*`) is `Safe` and picked by **Select safe** | `com.apple.*` children of user/system cache folders are `Review` with an explanation | ✅ Done (`6330f2e`) |
| B3 | High | Root helper resolves programs through user-writable dirs (`/usr/local/bin`, `/opt/homebrew/bin`, linuxbrew) and passes that `PATH` to root children | `SystemRunner::trusted()`: fixed system search path, `env_clear()`, fixed `PATH`/`LC_ALL`; used by the helper | ✅ Done (`4e04b12`) |
| B4 | High | Linux AppImage + `pkexec`: `current_exe()` is inside the user's FUSE mount, which root cannot open | Elevate the AppImage file itself (`$APPIMAGE`, validated absolute regular file) when present | ✅ Done (`4e04b12`); end-to-end `pkexec` run needs a Linux desktop session → owner check |
| B5 | High | Real "Move to Trash" and macOS admin clean never verified | Ignored integration test that trashes a disposable file via `SystemTrash`, run locally on macOS. Admin clean needs an interactive password prompt → owner check | ✅ Trash verified (`498f70b`); admin password prompt → owner check |
| B6 | Med | Confirm dialog in Trash mode does not say which items are removed permanently (Trash emptying, tool commands, admin items) | Dialog counts and lists permanent items in Trash mode | ✅ Done (`dd0584a`) |
| B7 | Med | systemd journal reports total usage, but `--vacuum-time=7d` frees only older files | Estimate = archived journal files older than 7 days; total usage shown in the detail; unknown when unreadable | ✅ Done (`9dc9a2f`) |
| B8 | Med | `KnownCommand::FlatpakUninstallUnused` is in the allowlist without a scanner | Removed (shrinks the allowlist) | ✅ Done (`32b6454`) |
| B9 | Med | DNF5 cache (`/var/cache/libdnf5`, Fedora 41+) not covered | New rule, cleaned with `dnf clean all` | ✅ Done (`32b6454`) |
| B10 | Med | Cancelled scan shows partially-measured sizes as real | `SizeReport::complete`; findings whose measurement was cut short are dropped | ✅ Done (`147d399`) |
| B11 | Med | UI test hard-codes the audit path and fails when `XDG_STATE_HOME` is set | Test resolves the path with the same function as the worker | ✅ Done (`dd0584a`) |
| B12 | Low | Selection survives a rescan | Selection cleared when a scan starts | ✅ Done (`dd0584a`) |
| B13 | Low | `encode_payload` swallows serialization errors | Returns `Result`; caller reports the error | ✅ Done (`4e04b12`) |
| B14 | Low | Generic `.cache/*` / `Library/Caches/*` rules walk folders that specific rules also walk | Children equal to an applicable specific rule's target are skipped | ✅ Done (`6330f2e`) |
| B15 | Low | Default project root `~/Documents` triggers a macOS privacy prompt with no warning | Welcome screen and README explain the prompt and how to remove the folder | ✅ Done (`dd0584a`) |

## 4. Features (PR 2)

| ID | Feature | Scope | Status |
|---|---|---|---|
| F1 | **Age filter** | Walker records the newest modification time; findings carry `last_modified`; table column "Last modified"; filter *Any / 7 / 30 / 90 / 180 days*; CLI `--older-than` | PR 2 |
| F2 | **Persisted settings** | `settings.json` (macOS `~/Library/Application Support/diskdust`, Linux `$XDG_CONFIG_HOME/diskdust`): project folders, delete mode, age filter, ignored items; per-row *Ignore*, *Show ignored* toggle | PR 2 |
| F3 | **Old developer toolchains** | rustup toolchains other than default/active (`rustup toolchain uninstall`), nvm and fnm Node versions other than the default, pyenv versions other than the global one, older JetBrains IDE config folders, Android system images and AVDs — all `Review` | PR 2 |
| F4 | **Installers** | `/Applications/Install macOS *.app`; `.dmg`/`.pkg`/`.iso` in `~/Downloads` older than 30 days (`Review`) | PR 2 |
| F5 | **VM disks (info)** | Lima (`~/.lima/<vm>/{disk,diffdisk,basedisk}`, `_disks`) and Colima (`~/.colima/_lima/...`) shown as informational items with guidance | PR 2 |
| F6 | **Running-app guard** | Findings carry the process that must not be running (Slack, Chrome, VS Code, Cursor, Discord, Xcode); the cleaner refuses them while it runs (`pgrep -x`) | PR 2 |
| F7 | **CLI clean** | `diskdust clean [--dry-run] [--safe-only] [--category C] [--older-than N] [--permanent] [--yes] [--json]`; admin items are listed but skipped | PR 2 |
| F8 | **Details & drill-down** | Selecting a row opens a details panel; "Largest folders" measures children in the background | PR 2 |
| F9 | **Free space, Empty Trash, History** | Free/total disk space in the toolbar (refreshed after cleans); *Empty Trash* action after a Trash-mode clean; History window reading the audit log | PR 2 |
| F10 | **More orphan locations** | `Saved Application State`, `HTTPStorages`, `WebKit` per bundle id | PR 2 |
| F11 | **Full Disk Access guidance** | Detects missing FDA on macOS; banner with a button opening the Privacy pane | PR 2 |

### Deferred (with reason)

| Item | Reason |
|---|---|
| Sandboxed app caches (`~/Library/Containers/*/Data/Library/Caches`) | macOS 14+ *App Data* protection prompts per container owner; needs a design for consent before scanning |
| Simulator runtimes (`xcrun simctl runtime`) | `simctl` unavailable on the verification machine — output format cannot be verified |
| OrbStack, Podman machine, UTM, Parallels disks | Disk locations not verifiable on the verification machine |
| Orphan detection by plain folder name | High false-positive rate (`Code`, `Google`, `Knowledge`, …) |
| Notarised builds, auto-update, scheduled cleanups | Need an Apple Developer ID / signing infrastructure (unchanged from `PLAN.md` §7) |

## 5. Verification per PR

Both PRs must pass, locally and in CI:

```
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --no-fail-fast
cargo llvm-cov --locked -p diskdust-core --fail-under-lines 80
cargo audit --deny warnings
cargo deny --locked check
```
