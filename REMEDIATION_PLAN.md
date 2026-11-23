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
| F1 | **Age filter** | Walker records the newest modification time; findings carry `last_modified`; table column "Last modified"; filter *Any / 7 / 30 / 90 / 180 days*; CLI `--older-than` | ✅ Done (`db80aa3`) |
| F2 | **Persisted settings** | `settings.json` (macOS `~/Library/Application Support/diskdust`, Linux `$XDG_CONFIG_HOME/diskdust`): project folders, delete mode, age filter, ignored items; per-row *Ignore*, *Show ignored* toggle | ✅ Done (`9f2e3ff`) |
| F3 | **Old developer toolchains** | rustup toolchains other than default/active (`rustup toolchain uninstall`), nvm and fnm Node versions other than the default, pyenv versions other than the global one, older JetBrains IDE config folders, Android system images and AVDs — all `Review` | ✅ Done (`76d8a9a`) |
| F4 | **Installers** | `/Applications/Install macOS *.app`; `.dmg`/`.pkg`/`.iso` in `~/Downloads` older than 30 days (`Review`) | ✅ Done (`2e73731`) |
| F5 | **VM disks (info)** | Lima (`~/.lima/<vm>/{disk,diffdisk,basedisk}`, `_disks`) and Colima (`~/.colima/_lima/...`) shown as informational items with guidance | ✅ Done (`2e73731`) |
| F6 | **Running-app guard** | Findings carry the process that must not be running (Slack, Chrome, VS Code, Cursor, Discord, Xcode); the cleaner refuses them while it runs (`pgrep -f` on macOS, `pgrep -x` on Linux; Linux process names not verified on a desktop) | ✅ Done (`d8273f8`) |
| F7 | **CLI clean** | `diskdust clean [--dry-run] [--safe-only] [--category C] [--older-than N] [--permanent] [--yes] [--json]`; admin items are listed but skipped | ✅ Done (`6892bbf`) |
| F8 | **Details & drill-down** | Selecting a row opens a details panel; "Largest folders" measures children in the background | ✅ Done (`021ad48, 52294be`) |
| F9 | **Free space, Empty Trash, History** | Free/total disk space in the toolbar (refreshed after cleans); *Empty Trash* action after a Trash-mode clean; History window reading the audit log | ✅ Done (`d5bf755, 52294be`) |
| F10 | **More orphan locations** | `Saved Application State`, `HTTPStorages`, `WebKit` per bundle id | ✅ Done (`bc835a0`) |
| F11 | **Full Disk Access guidance** | Detects missing FDA on macOS; banner with a button opening the Privacy pane | ✅ Done (`50ebb1b`) |

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

## 6. Second review (2026-11-23, `main` @ `4951cc9`)

Independent reviews of the engine, the app/CLI and the CI/release workflows, after F1–F11. Delivered
on `fix/review-2`; every fix has a regression test (or, for workflows, a local end-to-end check).

| ID | Sev. | Defect | Fix | Status |
|---|---|---|---|---|
| D1 | High | Trash emptied mid-clean: items moved to the Trash earlier in the same run were then erased with it | Trash-emptying actions always run first | ✅ `33b1ff7` |
| D2 | High | `clean --yes` without filters cleaned Review items (e.g. `docker volume prune`) and emptied the Trash | Safe items only unless `--include-review`; Trash only with `--category trash`; held-back items reported | ✅ `6191154` |
| D3 | High | pyenv offered the global interpreter (virtualenv name, trailing comment, prefix such as `3.12`) | Parse the version file like pyenv, resolve to installed versions, offer nothing if unresolvable, warn about envs inside | ✅ `1c2cb27` |
| D4 | High | One invalid field in `settings.json` reset the ignore list; CLI then cleaned ignored items, app overwrote the file | Per-field decoding; CLI refuses to clean, app backs up to `settings.json.bad` | ✅ `425dae6` |
| D5 | High | Root helper `chmod` fallback followed symlinks (TOCTOU → arbitrary file made writable as root) | Privileged cleaner never changes permissions | ✅ `856b73d` |
| D6 | Med | Running-app guard failed open when `pgrep` failed | Exit 1 = not running, anything else blocks (fail closed) | ✅ `6a39982` |
| D7 | Med | GUI cleaned ignored-but-ticked items and selections hidden by filters | One clean set for button, dialog and clean; dialog lists every item and hidden count | ✅ `a60902c` |
| D8 | Med | Linux packages needed glibc 2.39 (did not start on Ubuntu 22.04 / Debian 12) | Build on `ubuntu-22.04(-arm)`, `libc6 (>= 2.35)`, release step guards the requirement | ✅ `c5818ff` |
| D9 | Low | `clean` always exited 1 on macOS because skipped admin items counted as failures | Admin items held back and reported, never failed | ✅ `6954d5e` |
| D10 | Low | rustup not found from GUI launches; one rustup error dropped all toolchain results; `(override)` not kept | `~/.cargo/bin` searched; rustup errors isolated; override kept; dot-only names rejected | ✅ `4a760ab` |
| D11 | Low | Cleaning crossed mount points; old JetBrains settings could hold scratch files | Mount table check (fail closed); folders with scratches skipped | ✅ `0dca7f4`, `7c9b093` |
| D12 | Low | AppImage tools unpinned; release public before all assets; no approval gate; CI on `main` self-cancelled | Pinned + SHA-256-verified tools; draft-then-publish; `release` environment; misc. hardening | ✅ `5d5012e` |

Owner actions: add required reviewers to the `release` environment and enable branch protection
on `main` (R5).

## 7. Features after the second review (`feat/more-features`, stacked on `fix/review-2`)

| ID | Feature | Scope | Status |
|---|---|---|---|
| F12 | Measured space freed | Free space of the home volume before/after each clean, shown as "free space +X (measured)" in the app and CLI | ✅ `14833c0` |
| F13 | Large files (opt-in) | Files ≥ 1 GB in the home folder no rule explains; Review; never inside hidden folders, `.git`, `~/Library`, Trash or packages/libraries; CLI needs `--category large-files` | ✅ `fb13f15` |
| F14 | Docker items one by one | Each unused image (`docker image rm <id>`, unique size, age) and volume (`docker volume rm <name>`) from `docker system df -v`; validated ids/names; prune fallback | ✅ `7fbf9c8` |
| F15 | Your own rules | `custom_rules` in `settings.json`, confined to home, same safety policy, protected folders refused, skipped rules shown | ✅ `98ee470` |
| F16 | Undo | History / `diskdust undo` restore the last Trash-mode clean on Linux (never overwrite); macOS lists items and opens the Trash | ✅ `127bfbb` |
| F17 | More targets | Homebrew sized by its own cleanup estimate (covers autoremove and old cask versions); duplicate files in Downloads with a re-verified `RemoveDuplicate` action that never removes the last copy | ✅ `14ecde7`, `2698135` |
| F18 | Weekly report | `diskdust report`, `diskdust schedule`, sidebar toggle; LaunchAgent / systemd user timer; read-only | ✅ `157a45d` |

Considered and not added: Messages attachments (deleting files directly breaks Messages' database;
macOS Storage settings manage them; needs Full Disk Access) and Mail Downloads (another app's
container, same consent issue as the deferred sandboxed caches).
