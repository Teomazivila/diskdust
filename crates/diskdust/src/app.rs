//! The egui application.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::Instant;

use diskdust_core::clean::DeleteMode;
use diskdust_core::model::{Category, CleanupAction, Finding, Os, Privilege, Risk};
use diskdust_core::scan::ScanEvent;
use diskdust_core::scanners::{default_project_roots, unique_dirs};
use egui::{Align, Color32, Layout, RichText, Sense, vec2};
use egui_extras::{Column, TableBuilder};

use crate::format;
use crate::settings::{Loaded, Settings, SettingsStore};
use crate::worker::{self, CleanResult, Msg, Notifier};

const SAFE: Color32 = Color32::from_rgb(102, 187, 106);
const REVIEW: Color32 = Color32::from_rgb(255, 183, 77);
const INFO: Color32 = Color32::from_rgb(144, 164, 174);
const ADMIN: Color32 = Color32::from_rgb(100, 181, 246);
const DANGER: Color32 = Color32::from_rgb(229, 115, 115);
const ACCENT: Color32 = Color32::from_rgb(126, 87, 194);
const MAX_ACTIVITY: usize = 300;
/// Entries shown in the History window.
const HISTORY_LIMIT: usize = 300;
/// Choices of the "last modified" filter, in days (`None` = any age).
const AGE_FILTERS: [Option<u32>; 5] = [None, Some(7), Some(30), Some(90), Some(180)];

// Every icon the UI draws. They must exist in the bundled fonts (see `all_icons_have_glyphs`).
const ICON_REMOVE: &str = "×";
const ICON_OK: &str = "✔";
const ICON_FAIL: &str = "✖";
const ICON_REVEAL: &str = "↗";
const ICON_LOCK: &str = "🔒";
const ICON_WARN: &str = "⚠";
#[cfg(test)]
const ALL_ICONS: [&str; 6] = [ICON_REMOVE, ICON_OK, ICON_FAIL, ICON_REVEAL, ICON_LOCK, ICON_WARN];

/// Pure black background with slightly lifted surfaces so inputs and rows stay distinguishable.
const BG: Color32 = Color32::BLACK;
const SURFACE: Color32 = Color32::from_rgb(16, 16, 19);
const SURFACE_STRIPE: Color32 = Color32::from_rgb(11, 11, 13);
const BORDER: Color32 = Color32::from_rgb(38, 38, 44);

#[derive(Debug)]
enum Phase {
    /// No scan has run yet.
    Welcome,
    Idle,
    Scanning {
        started: Instant,
        running: Vec<&'static str>,
        finished: usize,
    },
    Cleaning {
        total: usize,
        done: usize,
    },
}

#[derive(Debug)]
struct Activity {
    ok: bool,
    text: String,
}

/// Outcome totals of the clean currently running or last finished.
#[derive(Debug, Default)]
struct CleanTally {
    freed: u64,
    trashed: u64,
    ok: usize,
    failed: usize,
    /// Measured change in free space of the home volume over the clean.
    disk_gain: Option<i64>,
}

#[derive(Debug)]
pub struct DiskdustApp {
    os: Os,
    home: PathBuf,
    findings: Vec<Finding>,
    selected: HashSet<String>,
    category: Option<Category>,
    search: String,
    /// Only show items not modified for at least this many days.
    older_than: Option<u32>,
    /// Finding ids the user chose to ignore (persisted).
    ignored: std::collections::BTreeSet<String>,
    show_ignored: bool,
    /// True once the user edited the project folders (then they are persisted).
    roots_customized: bool,
    store: SettingsStore,
    /// Last settings written, to save only on change.
    saved: Settings,
    /// Finding shown in the details panel.
    details: Option<String>,
    breakdown: Breakdown,
    /// Free / total space of the home volume.
    disk: Option<diskdust_core::disk::DiskSpace>,
    /// Offer "Empty Trash" after a clean moved items there.
    offer_empty_trash: bool,
    /// Entries shown in the History window, when open.
    history: Option<Vec<diskdust_core::audit::AuditEntry>>,
    /// macOS Full Disk Access as probed at start; `None` once dismissed or when not applicable.
    full_disk_access: Option<bool>,
    mode: DeleteMode,
    project_roots: Vec<PathBuf>,
    phase: Phase,
    cancel: Arc<AtomicBool>,
    notifier: Notifier,
    rx: Receiver<Msg>,
    /// Open confirmation dialog, if any.
    dialog: Option<Dialog>,
    activity: Vec<Activity>,
    status: String,
    tally: CleanTally,
}

impl DiskdustApp {
    pub fn new(cc: &eframe::CreationContext<'_>, os: Os, home: PathBuf, store: SettingsStore) -> Self {
        configure_style(&cc.egui_ctx);
        let (tx, rx) = channel();
        let Loaded { settings: saved, problem: settings_problem } = store.load();
        let roots_customized = saved.project_roots.is_some();
        let project_roots = saved.project_roots.clone().map_or_else(|| default_project_roots(&home), unique_dirs);
        Self {
            os,
            home,
            findings: Vec::new(),
            selected: HashSet::new(),
            category: None,
            search: String::new(),
            older_than: saved.older_than,
            ignored: saved.ignored.clone(),
            show_ignored: false,
            roots_customized,
            store,
            mode: saved.mode.unwrap_or(DeleteMode::Trash),
            project_roots,
            phase: Phase::Welcome,
            cancel: Arc::new(AtomicBool::new(false)),
            notifier: Notifier::new(tx, cc.egui_ctx.clone()),
            rx,
            dialog: None,
            activity: Vec::new(),
            status: "Ready. Scanning only reads; nothing is removed until you confirm.".to_owned(),
            tally: CleanTally::default(),
            saved,
            details: None,
            breakdown: Breakdown::None,
            disk: None,
            offer_empty_trash: false,
            history: None,
            full_disk_access: None,
        }
        .with_disk_space()
        .with_access_probe()
        .with_settings_problem(settings_problem)
    }

    /// Keeps an unreadable settings file safe before anything is saved over it, and says so.
    fn with_settings_problem(mut self, problem: Option<String>) -> Self {
        let Some(problem) = problem else { return self };
        let backup = match self.store.back_up() {
            Ok(Some(path)) => format!(" A copy was saved to {}.", path.display()),
            Ok(None) => String::new(),
            Err(e) => format!(" Could not back it up: {e}."),
        };
        self.status = format!("Some settings could not be read and were reset.{backup}");
        self.log(false, format!("{problem}.{backup}"));
        self
    }

    fn with_access_probe(mut self) -> Self {
        self.full_disk_access = diskdust_core::access::has_full_disk_access(self.os, &self.home);
        self
    }

    /// Explains what is missing without Full Disk Access and links to the setting.
    fn access_banner(&mut self, ui: &mut egui::Ui) {
        if self.full_disk_access != Some(false) {
            return;
        }
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, ADMIN))
            .corner_radius(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(
                            "diskdust cannot read your Trash and some app data without Full Disk Access, so their \
                             sizes show as unknown.",
                        )
                        .color(ADMIN),
                    );
                    if ui.button("Open Privacy settings").clicked()
                        && let Err(e) = opener::open(diskdust_core::access::FULL_DISK_ACCESS_SETTINGS)
                    {
                        self.log(false, format!("Could not open System Settings: {e}"));
                    }
                    if ui.button("Dismiss").clicked() {
                        self.full_disk_access = None;
                    }
                });
            });
        ui.add_space(6.0);
    }

    fn with_disk_space(mut self) -> Self {
        self.refresh_disk();
        self
    }

    fn refresh_disk(&mut self) {
        self.disk = diskdust_core::disk::space(&self.home);
    }

    fn open_history(&mut self) {
        let log = crate::session::default_audit_log(self.os, &self.home);
        match log.read_recent(HISTORY_LIMIT) {
            Ok(entries) => self.history = Some(entries),
            Err(e) => self.log(false, format!("Could not read {}: {e}", log.path().display())),
        }
    }

    fn start_empty_trash(&mut self) {
        self.offer_empty_trash = false;
        self.tally = CleanTally::default();
        self.phase = Phase::Cleaning { total: 1, done: 0 };
        "Emptying the Trash…".clone_into(&mut self.status);
        worker::spawn_empty_trash(self.os, self.home.clone(), self.notifier.clone());
    }

    fn history_window(&mut self, ctx: &egui::Context) {
        let Some(entries) = &self.history else { return };
        let mut open = true;
        egui::Window::new("Cleanup history")
            .open(&mut open)
            .anchor(egui::Align2::CENTER_TOP, vec2(0.0, 70.0))
            .min_width(640.0)
            .min_height(240.0)
            .collapsible(false)
            .show(ctx, |ui| {
                if entries.is_empty() {
                    ui.label(RichText::new("Nothing has been cleaned yet.").weak());
                    return;
                }
                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("history-grid").striped(true).num_columns(4).spacing(vec2(12.0, 4.0)).show(
                        ui,
                        |ui| {
                            for e in entries {
                                ui.label(
                                    RichText::new(e.timestamp.get(..16).unwrap_or(&e.timestamp).replace('T', " "))
                                        .small(),
                                );
                                let (icon, color) = if e.ok { (ICON_OK, SAFE) } else { (ICON_FAIL, DANGER) };
                                ui.label(RichText::new(icon).color(color));
                                ui.label(&e.title).on_hover_text(&e.message);
                                ui.label(RichText::new(format::maybe_bytes(e.bytes)).small());
                                ui.end_row();
                            }
                        },
                    );
                });
            });
        if !open {
            self.history = None;
        }
    }

    fn empty_trash_modal(&mut self, ctx: &egui::Context) {
        let mut confirmed = false;
        let mut cancelled = false;
        let modal = egui::Modal::new(egui::Id::unique("empty-trash")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.heading("Empty the Trash?");
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Everything in the Trash is deleted permanently, including items you moved there before. \
                     This cannot be undone.",
                )
                .color(DANGER),
            );
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(RichText::new("Empty Trash").strong()).fill(DANGER)).clicked() {
                    confirmed = true;
                }
                if ui.button("Cancel").clicked() {
                    cancelled = true;
                }
            });
        });
        if confirmed {
            self.dialog = None;
            self.start_empty_trash();
        } else if cancelled || modal.should_close() {
            self.dialog = None;
        }
    }

    fn current_settings(&self) -> Settings {
        Settings {
            project_roots: self.roots_customized.then(|| self.project_roots.clone()),
            mode: Some(self.mode),
            older_than: self.older_than,
            ignored: self.ignored.clone(),
        }
    }

    /// Saves settings when they changed since the last write.
    fn persist(&mut self) {
        let current = self.current_settings();
        let unchanged = current.project_roots == self.saved.project_roots
            && current.mode.unwrap_or(DeleteMode::Trash) == self.saved.mode.unwrap_or(DeleteMode::Trash)
            && current.older_than == self.saved.older_than
            && current.ignored == self.saved.ignored;
        if unchanged {
            return;
        }
        if let Err(e) = self.store.save(&current) {
            tracing::warn!(error = %e, "could not save settings");
        }
        self.saved = current;
    }

    fn open_details(&mut self, id: String) {
        if self.details.as_ref() != Some(&id) {
            self.breakdown = Breakdown::None;
        }
        self.details = Some(id);
    }

    fn close_details(&mut self) {
        self.details = None;
        self.breakdown = Breakdown::None;
    }

    fn request_breakdown(&mut self, id: String, path: PathBuf) {
        self.breakdown = Breakdown::Loading(id.clone());
        worker::spawn_breakdown(id, path, self.notifier.clone());
    }

    /// Right-hand panel describing the finding picked in the table.
    fn details_panel(&mut self, ui: &mut egui::Ui) {
        let Some(f) = self.details.as_ref().and_then(|id| self.findings.iter().find(|f| &f.id == id)).cloned() else {
            return;
        };
        let mut action = None;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading(RichText::new(&f.title).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    action = Some(DetailsAction::Close);
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            risk_cell(ui, &f);
            ui.label(RichText::new(f.category.label()).weak());
            if f.privilege == Privilege::Admin {
                ui.label(RichText::new(format!("{ICON_LOCK} admin")).color(ADMIN));
            }
        });
        ui.add_space(6.0);
        egui::Grid::new("details-grid").num_columns(2).spacing(vec2(10.0, 4.0)).show(ui, |ui| {
            ui.label(RichText::new("Size").weak());
            ui.label(format::maybe_bytes(f.bytes));
            ui.end_row();
            ui.label(RichText::new("Modified").weak());
            ui.label(format::age(f.age_days(format::now_unix())));
            ui.end_row();
            if let Some(path) = &f.path {
                ui.label(RichText::new("Path").weak());
                ui.label(RichText::new(display_path(path, &self.home)).small())
                    .on_hover_text(path.display().to_string());
                ui.end_row();
            }
            ui.label(RichText::new("Cleaning").weak());
            ui.label(action_description(&f, self.mode));
            ui.end_row();
        });
        ui.add_space(6.0);
        ui.label(&f.detail);
        if let Some(quit) = &f.quit_first {
            ui.add_space(4.0);
            ui.label(RichText::new(format!("{ICON_WARN} Quit {} before cleaning.", quit.app)).color(REVIEW));
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if let Some(path) = &f.path
                && ui.button("Reveal").clicked()
            {
                action = Some(DetailsAction::Row(RowAction::Reveal(path.clone())));
            }
            let ignore = if self.ignored.contains(&f.id) { "Stop ignoring" } else { "Ignore" };
            if ui.button(ignore).clicked() {
                action = Some(DetailsAction::Row(RowAction::ToggleIgnore(f.id.clone())));
            }
            if let Some(path) = f.path.as_ref().filter(|p| p.is_dir())
                && ui
                    .add_enabled(!matches!(self.breakdown, Breakdown::Loading(_)), egui::Button::new("Largest folders"))
                    .clicked()
            {
                action = Some(DetailsAction::Breakdown(path.clone()));
            }
        });
        match &self.breakdown {
            Breakdown::Loading(id) if *id == f.id => {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Measuring…");
                });
            }
            Breakdown::Ready(id, entries) if *id == f.id => {
                ui.add_space(6.0);
                ui.label(RichText::new("Largest folders").strong());
                let max = entries.first().map_or(1, |(_, b)| (*b).max(1));
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (path, bytes) in entries {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(file_name_of(path)).small())
                                .on_hover_text(path.display().to_string());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(format::bytes(*bytes)).small());
                            });
                        });
                        #[allow(clippy::cast_precision_loss)]
                        size_bar(ui, *bytes as f32 / max as f32);
                    }
                    if entries.is_empty() {
                        ui.label(RichText::new("No sub-folders to show.").weak());
                    }
                });
            }
            _ => {}
        }
        match action {
            Some(DetailsAction::Close) => self.close_details(),
            Some(DetailsAction::Row(row)) => self.apply(row),
            Some(DetailsAction::Breakdown(path)) => self.request_breakdown(f.id.clone(), path),
            None => {}
        }
    }

    fn is_ignored(&self, f: &Finding) -> bool {
        self.ignored.contains(&f.id)
    }

    fn toggle_ignored(&mut self, id: &str) {
        if !self.ignored.remove(id) {
            self.ignored.insert(id.to_owned());
            self.selected.remove(id);
        }
    }

    const fn busy(&self) -> bool {
        matches!(self.phase, Phase::Scanning { .. } | Phase::Cleaning { .. })
    }

    fn log(&mut self, ok: bool, text: String) {
        self.activity.push(Activity { ok, text });
        if self.activity.len() > MAX_ACTIVITY {
            self.activity.remove(0);
        }
    }

    /// Resets state for a new scan. Split from [`Self::start_scan`] so it can be tested without
    /// starting a real scan of the machine.
    fn begin_scan(&mut self) {
        // Sizes and items change between scans; never carry a stale selection into a new one.
        self.selected.clear();
        self.cancel = Arc::new(AtomicBool::new(false));
        self.phase = Phase::Scanning { started: Instant::now(), running: Vec::new(), finished: 0 };
        "Scanning…".clone_into(&mut self.status);
    }

    fn start_scan(&mut self) {
        self.begin_scan();
        worker::spawn_scan(
            self.os,
            self.home.clone(),
            self.project_roots.clone(),
            Arc::clone(&self.cancel),
            self.notifier.clone(),
        );
    }

    /// What a clean would remove right now: selected, actionable and not ignored. The toolbar
    /// button, the confirmation dialog and the clean itself all use this one definition.
    fn clean_set(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| self.selected.contains(&f.id) && f.is_actionable() && !self.is_ignored(f))
            .collect()
    }

    fn start_clean(&mut self) {
        let items: Vec<Finding> = self.clean_set().into_iter().cloned().collect();
        if items.is_empty() {
            return;
        }
        self.tally = CleanTally::default();
        self.phase = Phase::Cleaning { total: items.len(), done: 0 };
        self.status = format!("Cleaning {}…", format::items(items.len()));
        worker::spawn_clean(self.os, self.home.clone(), items, self.mode, self.notifier.clone());
    }

    fn drain_messages(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Scan(event) => self.on_scan_event(event),
                Msg::ScanDone { findings, elapsed, cancelled } => {
                    self.selected.retain(|id| findings.iter().any(|f| &f.id == id));
                    self.findings = findings;
                    if self.details.as_ref().is_some_and(|id| !self.findings.iter().any(|f| &f.id == id)) {
                        self.close_details();
                    }
                    let total: u64 =
                        self.findings.iter().filter(|f| f.is_actionable()).map(Finding::bytes_or_zero).sum();
                    self.status = format!(
                        "{} in {} · {} items · {} reclaimable",
                        if cancelled { "Scan cancelled" } else { "Scanned" },
                        format::duration(elapsed),
                        self.findings.len(),
                        format::bytes(total)
                    );
                    self.phase = Phase::Idle;
                    self.refresh_disk();
                }
                Msg::Cleaned(result) => self.on_cleaned(&result),
                Msg::Breakdown { id, entries } => {
                    if self.details.as_deref() == Some(id.as_str()) {
                        self.breakdown = Breakdown::Ready(id, entries);
                    }
                }
                Msg::CleanDone { disk_gain } => {
                    self.tally.disk_gain = disk_gain;
                    self.status = clean_summary(&self.tally);
                    self.phase = Phase::Idle;
                    self.offer_empty_trash = self.tally.trashed > 0;
                    self.refresh_disk();
                    if self.history.is_some() {
                        self.open_history();
                    }
                }
            }
        }
    }

    fn on_scan_event(&mut self, event: ScanEvent) {
        if let Phase::Scanning { running, finished, .. } = &mut self.phase {
            match &event {
                ScanEvent::Started { name, .. } => running.push(name),
                ScanEvent::Finished { name, .. } => {
                    running.retain(|n| n != name);
                    *finished += 1;
                }
            }
        }
        if let ScanEvent::Finished { name, error: Some(error), .. } = event {
            self.log(false, format!("{name}: {error}"));
        }
    }

    fn on_cleaned(&mut self, r: &CleanResult) {
        if let Phase::Cleaning { done, .. } = &mut self.phase {
            *done += 1;
        }
        if r.ok {
            self.tally.ok += 1;
            let bytes = r.bytes.unwrap_or(0);
            if r.trashed {
                self.tally.trashed += bytes;
            } else {
                self.tally.freed += bytes;
            }
            self.findings.retain(|f| f.id != r.id);
            self.selected.remove(&r.id);
            if self.details.as_deref() == Some(r.id.as_str()) {
                self.close_details();
            }
        } else {
            self.tally.failed += 1;
        }
        self.log(r.ok, format!("{} — {}", r.title, r.message));
    }

    fn visible(&self) -> Vec<usize> {
        let needle = self.search.to_lowercase();
        let now = format::now_unix();
        self.findings
            .iter()
            .enumerate()
            .filter(|(_, f)| self.category.is_none_or(|c| f.category == c))
            .filter(|(_, f)| self.show_ignored || !self.is_ignored(f))
            .filter(|(_, f)| {
                self.older_than.is_none_or(|days| f.age_days(now).is_some_and(|age| age >= u64::from(days)))
            })
            .filter(|(_, f)| {
                needle.is_empty()
                    || f.title.to_lowercase().contains(&needle)
                    || f.detail.to_lowercase().contains(&needle)
                    || f.path.as_ref().is_some_and(|p| p.to_string_lossy().to_lowercase().contains(&needle))
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Adds every visible, actionable finding matching `keep` to the selection.
    fn select_visible(&mut self, keep: impl Fn(&Finding) -> bool) {
        for i in self.visible() {
            let f = &self.findings[i];
            if f.is_actionable() && !self.is_ignored(f) && keep(f) {
                self.selected.insert(f.id.clone());
            }
        }
    }

    fn selection_summary(&self) -> (usize, u64) {
        self.clean_set().iter().fold((0, 0), |(n, b), f| (n + 1, b + f.bytes_or_zero()))
    }

    // ---- Panels ------------------------------------------------------------------------------

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("diskdust").size(22.0).strong().color(ACCENT));
            ui.label(RichText::new("find and reclaim hidden disk space").weak());
            if let Some(disk) = self.disk {
                ui.separator();
                ui.label(format!("{} free of {}", format::bytes(disk.available), format::bytes(disk.total)))
                    .on_hover_text("Space available on the volume holding your home folder");
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (count, bytes) = self.selection_summary();
                let clean_label = if count == 0 {
                    "Clean selected".to_owned()
                } else {
                    format!("Clean {count} · {}", format::bytes(bytes))
                };
                let clean = egui::Button::new(RichText::new(clean_label).strong()).fill(if count > 0 {
                    ACCENT
                } else {
                    ui.visuals().widgets.inactive.weak_bg_fill
                });
                if ui.add_enabled(count > 0 && !self.busy(), clean).clicked() {
                    self.dialog = Some(Dialog::ConfirmClean);
                }
                ui.separator();
                ui.selectable_value(&mut self.mode, DeleteMode::Permanent, "Delete permanently")
                    .on_hover_text("Remove files immediately. Cannot be undone.");
                ui.selectable_value(&mut self.mode, DeleteMode::Trash, "Move to Trash")
                    .on_hover_text("Recoverable. Space is reclaimed when you empty the Trash.");
                ui.separator();
                if ui.button("History").on_hover_text("Previous cleanups (from the audit log)").clicked() {
                    self.open_history();
                }
                if let Phase::Scanning { .. } = self.phase {
                    if ui.button("Cancel scan").clicked() {
                        self.cancel.store(true, Ordering::Relaxed);
                    }
                } else {
                    let label = if matches!(self.phase, Phase::Welcome) { "Scan" } else { "Rescan" };
                    if ui.add_enabled(!self.busy(), egui::Button::new(label)).clicked() {
                        self.start_scan();
                    }
                }
            });
        });
        ui.add_space(6.0);
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        let mut totals: BTreeMap<Category, Totals> = BTreeMap::new();
        let mut all = Totals::default();
        for f in self.findings.iter().filter(|f| !self.is_ignored(f)) {
            totals.entry(f.category).or_default().add(f);
            all.add(f);
        }
        category_row(ui, &mut self.category, None, "All items", &all);
        ui.add_space(4.0);
        for category in Category::ALL {
            if let Some(t) = totals.get(&category) {
                category_row(ui, &mut self.category, Some(category), category.label(), t);
            }
        }
        ui.add_space(8.0);
        ui.separator();
        ui.label(RichText::new("Selection").strong());
        ui.horizontal_wrapped(|ui| {
            let busy = self.busy();
            if ui
                .add_enabled(!busy, egui::Button::new("Select all"))
                .on_hover_text("Select every visible item, including ones marked Review")
                .clicked()
            {
                self.select_visible(|_| true);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Select safe"))
                .on_hover_text("Select every visible item marked Safe")
                .clicked()
            {
                self.select_visible(|f| f.risk == Risk::Safe);
            }
            if ui.add_enabled(!busy, egui::Button::new("Clear")).clicked() {
                self.selected.clear();
            }
        });
        ui.add_space(8.0);
        ui.separator();
        ui.label(RichText::new("Project folders").strong())
            .on_hover_text("Searched for target/, node_modules/ and other build output");
        let mut remove = None;
        for (i, root) in self.project_roots.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.busy(), egui::Button::new(ICON_REMOVE).small())
                    .on_hover_text("Remove")
                    .clicked()
                {
                    remove = Some(i);
                }
                ui.label(RichText::new(display_path(root, &self.home)).small())
                    .on_hover_text(root.display().to_string());
            });
        }
        if let Some(i) = remove {
            self.project_roots.remove(i);
            self.roots_customized = true;
        }
        if ui.add_enabled(!self.busy(), egui::Button::new("Add folder…")).clicked()
            && let Some(folder) = rfd::FileDialog::new().set_directory(&self.home).pick_folder()
        {
            let mut roots = self.project_roots.clone();
            roots.push(folder);
            self.project_roots = unique_dirs(roots);
            self.roots_customized = true;
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| match &self.phase {
            Phase::Scanning { started, running, finished } => {
                ui.spinner();
                let current = running.first().copied().unwrap_or("Finishing");
                ui.label(format!(
                    "Scanning… {finished} sources done · {current} · {}",
                    format::duration(started.elapsed())
                ));
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
            }
            Phase::Cleaning { total, done } => {
                ui.spinner();
                #[allow(clippy::cast_precision_loss)]
                let fraction = *done as f32 / (*total).max(1) as f32;
                ui.add(egui::ProgressBar::new(fraction).desired_width(200.0).text(format!("{done}/{total}")));
                ui.label(&self.status);
            }
            Phase::Idle | Phase::Welcome => {
                ui.label(&self.status);
                if self.offer_empty_trash && ui.button("Empty Trash…").clicked() {
                    self.dialog = Some(Dialog::EmptyTrash);
                }
            }
        });
        egui::CollapsingHeader::new(format!("Activity ({})", self.activity.len())).id_salt("activity").show(ui, |ui| {
            egui::ScrollArea::vertical().max_height(140.0).stick_to_bottom(true).show(ui, |ui| {
                for a in &self.activity {
                    let (icon, color) = if a.ok { (ICON_OK, SAFE) } else { (ICON_FAIL, DANGER) };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(icon).color(color));
                        ui.label(RichText::new(&a.text).small());
                    });
                }
            });
        });
        ui.add_space(4.0);
    }

    fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.25);
            ui.label(RichText::new("Where did my disk space go?").size(28.0).strong());
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "diskdust looks in Docker, ~/Library, developer caches, build folders and system caches.\n\
                     Scanning is read-only. Nothing is removed until you select items and confirm.",
                )
                .weak(),
            );
            if let Some(note) = privacy_prompt_note(self.os, &self.home, &self.project_roots) {
                ui.add_space(8.0);
                ui.label(RichText::new(note).small().color(INFO));
            }
            ui.add_space(18.0);
            let label = match self.os {
                Os::MacOs => "Scan this Mac",
                Os::Linux => "Scan this computer",
            };
            let button =
                egui::Button::new(RichText::new(label).size(18.0).strong()).fill(ACCENT).min_size(vec2(220.0, 44.0));
            if ui.add(button).clicked() {
                self.start_scan();
            }
        });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui, visible: &[usize]) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search).hint_text("Filter by name or path…").desired_width(280.0),
            );
            egui::ComboBox::from_id_salt("age-filter")
                .selected_text(age_filter_label(self.older_than))
                .show_ui(ui, |ui| {
                    for choice in AGE_FILTERS {
                        ui.selectable_value(&mut self.older_than, choice, age_filter_label(choice));
                    }
                })
                .response
                .on_hover_text("Show only items whose newest file or folder is at least this old");
            let mut shown = Totals::default();
            for i in visible {
                shown.add(&self.findings[*i]);
            }
            ui.label(RichText::new(format!("{} · {} reclaimable", format::items(shown.count), shown.label())).weak());
            let ignored = self.findings.iter().filter(|f| self.is_ignored(f)).count();
            if ignored > 0 || self.show_ignored {
                ui.checkbox(&mut self.show_ignored, format!("Show ignored ({ignored})"));
            }
        });
        ui.add_space(4.0);
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let visible = self.visible();
        self.filter_bar(ui, &visible);
        if visible.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                let text = if matches!(self.phase, Phase::Scanning { .. }) {
                    "Scanning…"
                } else {
                    "Nothing to show. Your disk is looking tidy."
                };
                ui.label(RichText::new(text).weak().size(16.0));
            });
            return;
        }
        let max_bytes = visible
            .iter()
            .map(|i| &self.findings[*i])
            .filter(|f| f.is_actionable())
            .map(Finding::bytes_or_zero)
            .max()
            .unwrap_or(1)
            .max(1);
        let busy = self.busy();
        let now = format::now_unix();
        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height * 2.0 + 14.0;
        let mut actions = Vec::new();
        // With the details panel open the Category column is dropped (the panel shows it), so Size
        // and Modified stay visible; each layout keeps its own column widths.
        let compact = self.details.is_some();
        let mut table = TableBuilder::new(ui)
            .id_salt(if compact { "results-compact" } else { "results" })
            .striped(true)
            .resizable(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(26.0))
            .column(Column::remainder().at_least(if compact { 180.0 } else { 260.0 }).clip(true));
        if !compact {
            table = table.column(Column::initial(140.0).at_least(90.0));
        }
        let titles: &[&str] = if compact {
            &["", "Item", "Risk", "Size", "Modified", ""]
        } else {
            &["", "Item", "Category", "Risk", "Size", "Modified", ""]
        };
        table
            .column(Column::exact(78.0))
            .column(Column::initial(130.0).at_least(100.0))
            .column(Column::initial(100.0).at_least(80.0))
            .column(Column::exact(34.0))
            .header(22.0, |mut header| {
                for &title in titles {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, visible.len(), |row| {
                    let f = &self.findings[visible[row.index()]];
                    self.table_row(row, f, RowContext { busy, now, max_bytes, compact }, &mut actions);
                });
            });
        for action in actions {
            self.apply(action);
        }
    }

    fn table_row(&self, mut row: egui_extras::TableRow<'_, '_>, f: &Finding, rc: RowContext, out: &mut Vec<RowAction>) {
        row.col(|ui| {
            let mut checked = self.selected.contains(&f.id);
            let enabled = f.is_actionable() && !rc.busy && !self.is_ignored(f);
            let response = ui.add_enabled(enabled, egui::Checkbox::without_text(&mut checked));
            let label = format!("Select {}", f.title);
            response.widget_info(|| egui::WidgetInfo::selected(egui::Role::CheckBox, enabled, checked, &label));
            if response.changed() {
                out.push(RowAction::Select(f.id.clone(), checked));
            }
        });
        let ignored = self.ignored.contains(&f.id);
        row.col(|ui| {
            let response = item_cell(ui, f, &self.home, ignored).on_hover_text("Click for details");
            if response.clicked() {
                out.push(RowAction::Details(f.id.clone()));
            }
            response.context_menu(|ui| {
                let label = if ignored { "Stop ignoring" } else { "Ignore this item" };
                if ui.button(label).clicked() {
                    out.push(RowAction::ToggleIgnore(f.id.clone()));
                    ui.close();
                }
            });
        });
        if !rc.compact {
            row.col(|ui| {
                ui.label(f.category.label());
            });
        }
        row.col(|ui| risk_cell(ui, f));
        row.col(|ui| size_cell(ui, f, rc.max_bytes));
        row.col(|ui| {
            ui.label(RichText::new(format::age(f.age_days(rc.now))).weak());
        });
        row.col(|ui| {
            if let Some(path) = &f.path
                && ui.small_button(ICON_REVEAL).on_hover_text("Reveal in file manager").clicked()
            {
                out.push(RowAction::Reveal(path.clone()));
            }
        });
    }

    fn apply(&mut self, action: RowAction) {
        match action {
            RowAction::Select(id, true) => {
                self.selected.insert(id);
            }
            RowAction::Select(id, false) => {
                self.selected.remove(&id);
            }
            RowAction::ToggleIgnore(id) => self.toggle_ignored(&id),
            RowAction::Details(id) => self.open_details(id),
            RowAction::Reveal(path) => {
                let target = if path.exists() { path } else { path.parent().map(PathBuf::from).unwrap_or(path) };
                if let Err(e) = opener::reveal(&target) {
                    self.log(false, format!("Could not reveal {}: {e}", target.display()));
                }
            }
        }
    }

    fn confirm_modal(&mut self, ctx: &egui::Context) {
        let chosen = self.clean_set();
        let visible: HashSet<&str> = self.visible().into_iter().map(|i| self.findings[i].id.as_str()).collect();
        let hidden = chosen.iter().filter(|f| !visible.contains(f.id.as_str())).count();
        let total: u64 = chosen.iter().map(|f| f.bytes_or_zero()).sum();
        let review = chosen.iter().filter(|f| f.risk == Risk::Review).count();
        let admin = chosen.iter().filter(|f| f.privilege == Privilege::Admin).count();
        let unknown = chosen.iter().filter(|f| f.bytes.is_none()).count();
        let mut quit_apps: Vec<&str> =
            chosen.iter().filter_map(|f| f.quit_first.as_ref().map(|q| q.app.as_str())).collect();
        quit_apps.sort_unstable();
        quit_apps.dedup();
        let permanent: Vec<&str> =
            chosen.iter().filter(|f| removed_permanently_in_trash_mode(f)).map(|f| f.title.as_str()).collect();
        let mut confirmed = false;
        let mut cancelled = false;
        let modal = egui::Modal::new(egui::Id::unique("confirm-clean")).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.heading(format!("Clean {}?", format::items(chosen.len())));
            ui.add_space(6.0);
            let mut size = format!("About {} will be reclaimed", format::bytes(total));
            if unknown > 0 {
                let _ = write!(size, " (plus {} of unknown size)", format::items(unknown));
            }
            ui.label(size);
            ui.add_space(6.0);
            chosen_list(ui, &chosen);
            if hidden > 0 {
                ui.label(
                    RichText::new(format!(
                        "{ICON_WARN} {} not shown by the current filter.",
                        if hidden == 1 { "1 of these is".to_owned() } else { format!("{hidden} of these are") }
                    ))
                    .color(REVIEW),
                );
            }
            ui.add_space(6.0);
            match self.mode {
                DeleteMode::Trash => {
                    ui.label("Files are moved to the Trash. Space is reclaimed when the Trash is emptied.");
                    if !permanent.is_empty() {
                        ui.add_space(6.0);
                        ui.label(RichText::new(permanent_warning(&permanent)).color(DANGER));
                    }
                }
                DeleteMode::Permanent => {
                    ui.label(RichText::new("Files are deleted permanently. This cannot be undone.").color(DANGER));
                }
            }
            if review > 0 {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "{ICON_WARN} {} marked Review and may contain data you want to keep.",
                        format::items_are(review)
                    ))
                    .color(REVIEW),
                );
            }
            if !quit_apps.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "{ICON_WARN} Quit {} first. Items of apps that are still running are skipped.",
                        quit_apps.join(", ")
                    ))
                    .color(REVIEW),
                );
            }
            if admin > 0 {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "{ICON_LOCK} {} administrator access. You will be asked for your password; \
                         these are always removed permanently.",
                        if admin == 1 { "1 item needs".to_owned() } else { format!("{admin} items need") }
                    ))
                    .color(ADMIN),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let label = match self.mode {
                    DeleteMode::Trash => format!("Clean {}", format::items(chosen.len())),
                    DeleteMode::Permanent => format!("Delete {} permanently", format::items(chosen.len())),
                };
                if ui.add(egui::Button::new(RichText::new(label).strong()).fill(DANGER)).clicked() {
                    confirmed = true;
                }
                if ui.button("Cancel").clicked() {
                    cancelled = true;
                }
            });
        });
        if confirmed {
            self.dialog = None;
            self.start_clean();
        } else if cancelled || modal.should_close() {
            self.dialog = None;
        }
    }
}

impl eframe::App for DiskdustApp {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_messages();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("sidebar").resizable(false).exact_size(240.0).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.sidebar(ui));
        });
        if self.details.is_some() && !matches!(self.phase, Phase::Welcome) {
            egui::Panel::right("details").resizable(true).default_size(320.0).show(ui, |ui| {
                egui::ScrollArea::vertical().id_salt("details-scroll").show(ui, |ui| self.details_panel(ui));
            });
        }
        egui::CentralPanel::default().show(ui, |ui| {
            self.access_banner(ui);
            if matches!(self.phase, Phase::Welcome) {
                self.welcome(ui);
            } else {
                self.table(ui);
            }
        });
        let ctx = ui.ctx().clone();
        match self.dialog {
            Some(Dialog::ConfirmClean) => self.confirm_modal(&ctx),
            Some(Dialog::EmptyTrash) => self.empty_trash_modal(&ctx),
            None => {}
        }
        self.history_window(&ctx);
        self.persist();
    }
}

fn age_filter_label(days: Option<u32>) -> String {
    days.map_or_else(|| "Any age".to_owned(), |d| format!("Untouched {d}+ days"))
}

/// Items that bypass the Trash even in Trash mode: emptying a trash folder, tool commands
/// (Docker, Homebrew, …) and admin items run by the privileged helper.
fn removed_permanently_in_trash_mode(f: &Finding) -> bool {
    f.privilege == Privilege::Admin || !matches!(f.action, Some(CleanupAction::RemovePath { .. }))
}

/// "2 items are removed permanently, not moved to the Trash: A, B." (at most 4 names).
fn permanent_warning(titles: &[&str]) -> String {
    const SHOWN: usize = 4;
    let mut names = titles.iter().take(SHOWN).copied().collect::<Vec<_>>().join(", ");
    if titles.len() > SHOWN {
        let _ = write!(names, " and {} more", titles.len() - SHOWN);
    }
    format!(
        "{ICON_WARN} {} removed permanently, not moved to the Trash: {names}. This cannot be undone.",
        format::items_are(titles.len())
    )
}

/// macOS asks before an app reads Documents, Desktop or Downloads. Explain the prompts up front:
/// Downloads is always checked for old installers; the others when a project folder lives there.
fn privacy_prompt_note(os: Os, home: &std::path::Path, roots: &[PathBuf]) -> Option<String> {
    if os != Os::MacOs {
        return None;
    }
    let projects: Vec<&str> = ["Documents", "Desktop"]
        .into_iter()
        .filter(|name| roots.iter().any(|r| r.starts_with(home.join(name))))
        .collect();
    let mut note = "macOS may ask to let diskdust access your Downloads folder, where it looks for old \
                    installers."
        .to_owned();
    if !projects.is_empty() {
        let _ = write!(
            note,
            " It may also ask for your {} folder: project folders there are searched for build output \
             (target/, node_modules/, …). Remove a folder under Project folders to skip it.",
            projects.join(" and ")
        );
    }
    Some(note)
}

/// Every item a clean will touch, so nothing selected under another filter goes unnoticed.
fn chosen_list(ui: &mut egui::Ui, chosen: &[&Finding]) {
    egui::ScrollArea::vertical().max_height(150.0).id_salt("chosen-items").show(ui, |ui| {
        egui::Grid::new("chosen-items-grid").num_columns(3).spacing(vec2(12.0, 4.0)).show(ui, |ui| {
            for f in chosen {
                ui.label(RichText::new(format::maybe_bytes(f.bytes)).weak());
                ui.label(&f.title);
                ui.label(RichText::new(f.category.label()).weak());
                ui.end_row();
            }
        });
    });
}

fn clean_summary(t: &CleanTally) -> String {
    let mut status = format!("Cleaned {}, freed {}", format::items(t.ok), format::bytes(t.freed));
    if t.trashed > 0 {
        let _ = write!(status, " · {} moved to Trash (empty the Trash to reclaim it)", format::bytes(t.trashed));
    }
    if t.failed > 0 {
        let _ = write!(status, " · {} failed (see Activity)", t.failed);
    }
    if let Some(gain) = t.disk_gain {
        let _ = write!(status, " · free space {} (measured)", format::signed_bytes(gain));
    }
    status
}

fn configure_style(ctx: &egui::Context) {
    ctx.set_visuals(visuals());
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = vec2(8.0, 6.0);
        style.spacing.button_padding = vec2(10.0, 5.0);
    });
}

fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.window_stroke = egui::Stroke::new(1.0, BORDER);
    v.extreme_bg_color = SURFACE;
    v.faint_bg_color = SURFACE_STRIPE;
    v.code_bg_color = SURFACE;
    v.selection.bg_fill = ACCENT;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    v
}

/// Per-frame values shared by every table row.
#[derive(Debug, Clone, Copy)]
struct RowContext {
    busy: bool,
    now: i64,
    max_bytes: u64,
    /// Details panel open: no Category column.
    compact: bool,
}

/// What the user did in a table row, applied after the table is drawn.
#[derive(Debug)]
enum RowAction {
    Select(String, bool),
    ToggleIgnore(String),
    Reveal(PathBuf),
    Details(String),
}

/// Confirmation dialogs (one at a time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialog {
    ConfirmClean,
    EmptyTrash,
}

/// What the user did in the details panel.
#[derive(Debug)]
enum DetailsAction {
    Close,
    Row(RowAction),
    Breakdown(PathBuf),
}

/// "Largest folders" state of the details panel, keyed by finding id.
#[derive(Debug)]
enum Breakdown {
    None,
    Loading(String),
    Ready(String, Vec<(PathBuf, u64)>),
}

/// What cleaning `f` does, in the current delete mode.
fn action_description(f: &Finding, mode: DeleteMode) -> String {
    match &f.action {
        None => "Information only; diskdust does not clean it.".to_owned(),
        Some(CleanupAction::Run(cmd)) => format!("Runs `{}`.", cmd.argv().join(" ")),
        Some(CleanupAction::EmptyDir { .. }) => "Permanently removes everything inside.".to_owned(),
        Some(CleanupAction::RemovePath { .. }) if f.privilege == Privilege::Admin => {
            "Removed permanently with administrator rights.".to_owned()
        }
        Some(CleanupAction::RemovePath { .. }) => match mode {
            DeleteMode::Trash => "Moved to the Trash.".to_owned(),
            DeleteMode::Permanent => "Deleted permanently.".to_owned(),
        },
    }
}

fn file_name_of(path: &std::path::Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

/// Item count and reclaimable size of a group of findings. Informational findings are counted
/// but never contribute bytes, since they cannot be cleaned.
#[derive(Debug, Default, Clone, Copy)]
struct Totals {
    count: usize,
    bytes: u64,
    unknown: bool,
}

impl Totals {
    fn add(&mut self, f: &Finding) {
        self.count += 1;
        if f.is_actionable() {
            match f.bytes {
                Some(b) => self.bytes += b,
                None => self.unknown = true,
            }
        }
    }

    fn label(&self) -> String {
        format::reclaimable(self.bytes, self.unknown)
    }
}

fn category_row(ui: &mut egui::Ui, current: &mut Option<Category>, value: Option<Category>, label: &str, t: &Totals) {
    let selected = *current == value;
    let text = RichText::new(format!("{label}  ({})", t.count));
    let response = ui.horizontal(|ui| {
        let r = ui.selectable_label(selected, if selected { text.strong() } else { text });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(t.label()).weak());
        });
        r
    });
    if response.inner.clicked() {
        *current = value;
    }
}

/// Title and path of a row. Both the title (keyboard / accessibility) and the whole cell (pointer)
/// are clickable; the returned response covers both.
fn item_cell(ui: &mut egui::Ui, f: &Finding, home: &std::path::Path, ignored: bool) -> egui::Response {
    let inner = ui.vertical(|ui| {
        let title = ui.horizontal(|ui| {
            let title = ui.add(egui::Label::new(RichText::new(&f.title).strong()).sense(Sense::click()));
            if ignored {
                ui.label(RichText::new("ignored").small().color(INFO));
            }
            if f.privilege == Privilege::Admin {
                ui.label(RichText::new(format!("{ICON_LOCK} admin")).small().color(ADMIN))
                    .on_hover_text("Requires your administrator password when cleaned");
            }
            title
        });
        let second =
            f.path.as_ref().map_or_else(|| f.detail.clone(), |p| format!("{} — {}", display_path(p, home), f.detail));
        ui.label(RichText::new(second).small().weak()).on_hover_text(&f.detail);
        title.inner
    });
    inner.response.interact(Sense::click()) | inner.inner
}

fn risk_cell(ui: &mut egui::Ui, f: &Finding) {
    let (text, color) = if !f.is_actionable() {
        ("Info", INFO)
    } else if f.risk == Risk::Safe {
        ("Safe", SAFE)
    } else {
        ("Review", REVIEW)
    };
    badge(ui, text, color);
}

fn size_cell(ui: &mut egui::Ui, f: &Finding, max_bytes: u64) {
    ui.vertical(|ui| {
        ui.label(format::maybe_bytes(f.bytes));
        if let (true, Some(bytes)) = (f.is_actionable(), f.bytes) {
            #[allow(clippy::cast_precision_loss)]
            size_bar(ui, bytes as f32 / max_bytes as f32);
        }
    });
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), egui::FontId::proportional(12.5), color);
    let (rect, response) = ui.allocate_exact_size(galley.size() + vec2(18.0, 8.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 9.0, color.gamma_multiply(0.16));
    painter.rect_stroke(rect, 9.0, egui::Stroke::new(1.0, color), egui::StrokeKind::Inside);
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text));
}

fn size_bar(ui: &mut egui::Ui, fraction: f32) {
    let width = ui.available_width().min(140.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, 5.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 2.0, ui.visuals().widgets.inactive.bg_fill);
    let mut filled = rect;
    filled.set_width((width * fraction.clamp(0.0, 1.0)).max(2.0));
    painter.rect_filled(filled, 2.0, ACCENT);
}

/// Shows paths under home as `~/…`.
fn display_path(path: &std::path::Path, home: &std::path::Path) -> String {
    path.strip_prefix(home).map_or_else(|_| path.display().to_string(), |rel| format!("~/{}", rel.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn clean_summary_mentions_trash_and_failures() {
        let t = CleanTally { freed: 2_000_000_000, trashed: 0, ok: 3, failed: 0, disk_gain: None };
        assert_eq!(clean_summary(&t), "Cleaned 3 items, freed 2.0 GB");
        let t = CleanTally { disk_gain: Some(2_100_000_000), ..t };
        assert_eq!(clean_summary(&t), "Cleaned 3 items, freed 2.0 GB · free space +2.1 GB (measured)");
        let t = CleanTally { freed: 0, trashed: 5_000_000, ok: 1, failed: 2, disk_gain: None };
        assert_eq!(
            clean_summary(&t),
            "Cleaned 1 item, freed 0 B · 5.0 MB moved to Trash (empty the Trash to reclaim it) · 2 failed (see Activity)"
        );
    }

    #[test]
    fn permanent_items_in_trash_mode() {
        let mut f = Finding {
            id: "x".into(),
            scanner: "t".into(),
            category: Category::Trash,
            title: "x".into(),
            detail: String::new(),
            path: None,
            bytes: None,
            risk: Risk::Safe,
            privilege: Privilege::User,
            action: Some(CleanupAction::RemovePath { path: "/a/b".into(), root: "/a".into() }),
            specificity: 0,
            last_modified: None,
            quit_first: None,
        };
        assert!(!removed_permanently_in_trash_mode(&f));
        f.privilege = Privilege::Admin;
        assert!(removed_permanently_in_trash_mode(&f), "the helper always deletes permanently");
        f.privilege = Privilege::User;
        f.action = Some(CleanupAction::EmptyDir { path: "/a/b".into(), root: "/a".into() });
        assert!(removed_permanently_in_trash_mode(&f));
        assert_eq!(
            permanent_warning(&["Trash"]),
            format!("{ICON_WARN} 1 item is removed permanently, not moved to the Trash: Trash. This cannot be undone.")
        );
        assert!(permanent_warning(&["a", "b", "c", "d", "e", "f"]).contains("a, b, c, d and 2 more"));
    }

    #[test]
    fn privacy_note_only_for_protected_mac_folders() {
        let home = Path::new("/Users/a");
        let docs = vec![PathBuf::from("/Users/a/Documents"), PathBuf::from("/Users/a/code")];
        assert!(privacy_prompt_note(Os::MacOs, home, &docs).expect("note").contains("your Documents folder"));
        assert!(privacy_prompt_note(Os::Linux, home, &docs).is_none());
        let only_code = privacy_prompt_note(Os::MacOs, home, &[PathBuf::from("/Users/a/code")]).expect("note");
        assert!(only_code.contains("Downloads") && !only_code.contains("Documents"));
    }

    #[test]
    fn action_descriptions() {
        let mut f = Finding {
            id: "x".into(),
            scanner: "t".into(),
            category: Category::Trash,
            title: "x".into(),
            detail: String::new(),
            path: None,
            bytes: None,
            risk: Risk::Safe,
            privilege: Privilege::User,
            action: None,
            specificity: 0,
            last_modified: None,
            quit_first: None,
        };
        assert!(action_description(&f, DeleteMode::Trash).starts_with("Information only"));
        f.action = Some(CleanupAction::Run(diskdust_core::model::KnownCommand::BrewCleanup));
        assert_eq!(action_description(&f, DeleteMode::Trash), "Runs `brew cleanup --prune=all`.");
        f.action = Some(CleanupAction::RemovePath { path: "/a/b".into(), root: "/a".into() });
        assert_eq!(action_description(&f, DeleteMode::Trash), "Moved to the Trash.");
        assert_eq!(action_description(&f, DeleteMode::Permanent), "Deleted permanently.");
        f.privilege = Privilege::Admin;
        assert!(action_description(&f, DeleteMode::Trash).contains("administrator"));
        assert_eq!(file_name_of(Path::new("/x/y")), "y");
    }

    #[test]
    fn display_path_abbreviates_home() {
        assert_eq!(display_path(Path::new("/Users/a/Library/Caches"), Path::new("/Users/a")), "~/Library/Caches");
        assert_eq!(display_path(Path::new("/Library/Caches"), Path::new("/Users/a")), "/Library/Caches");
    }

    mod ui {
        use super::super::*;
        use diskdust_core::model::{CleanupAction, KnownCommand, SPECIFIC};
        use egui_kittest::Harness;
        use egui_kittest::kittest::{NodeT as _, Queryable};
        use std::path::Path;
        use std::time::Duration;

        fn harness(home: &Path) -> Harness<'static, DiskdustApp> {
            let home = home.to_path_buf();
            Harness::builder().with_size(vec2(1200.0, 760.0)).build_eframe(move |cc| {
                DiskdustApp::new(cc, Os::current().expect("supported os"), home, SettingsStore::in_memory())
            })
        }

        fn finding(id: &str, title: &str, bytes: Option<u64>, risk: Risk, privilege: Privilege) -> Finding {
            Finding {
                id: id.into(),
                scanner: "test".into(),
                category: Category::DeveloperCaches,
                title: title.into(),
                detail: "Example detail text.".into(),
                path: None,
                bytes,
                risk,
                privilege,
                action: Some(CleanupAction::Run(KnownCommand::BrewCleanup)),
                specificity: SPECIFIC,
                last_modified: None,
                quit_first: None,
            }
        }

        fn sample() -> Vec<Finding> {
            let mut info =
                finding("raw", "Docker Desktop disk image", Some(64_400_000_000), Risk::Safe, Privilege::User);
            info.category = Category::Containers;
            info.action = None;
            let mut images =
                finding("images", "Unused Docker images", Some(32_300_000_000), Risk::Review, Privilege::User);
            images.category = Category::Containers;
            let mut snapshots = finding("tm", "Time Machine local snapshots", None, Risk::Review, Privilege::Admin);
            snapshots.category = Category::System;
            vec![
                info,
                images,
                finding("gobuild", "Go build cache", Some(18_800_000_000), Risk::Safe, Privilege::User),
                finding("brew", "Homebrew cache", Some(1_800_000_000), Risk::Safe, Privilege::User),
                snapshots,
            ]
        }

        /// When `DISKDUST_SCREENSHOTS` is set, renders the frame (needs a GPU or software rasterizer)
        /// and saves it under `<target dir>/screenshots` for visual review. Otherwise the UI tests
        /// run headless with no renderer, so they work on any CI machine.
        fn save(harness: &mut Harness<'_, DiskdustApp>, name: &str) {
            if std::env::var_os("DISKDUST_SCREENSHOTS").is_none() {
                return;
            }
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"), PathBuf::from);
            let dir = target.join("screenshots");
            let image = harness.render().expect("render frame");
            std::fs::create_dir_all(&dir).expect("create screenshot dir");
            image.save(dir.join(format!("{name}.png"))).expect("save png");
        }

        fn wait_until_idle(harness: &mut Harness<'_, DiskdustApp>) {
            for _ in 0..500 {
                harness.step();
                if !harness.state().busy() {
                    harness.run_steps(2);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("app did not become idle");
        }

        #[test]
        fn welcome_screen() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.run();
            let label = if cfg!(target_os = "macos") { "Scan this Mac" } else { "Scan this computer" };
            harness.get_by_label(label);
            harness.get_by_label("Clean selected");
            save(&mut harness, "welcome");
        }

        #[test]
        fn results_table_and_selection() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.run();
            harness.get_by_label("Unused Docker images");
            harness.get_by_label("Time Machine local snapshots");
            harness.get_by_label("Select safe").click();
            harness.run();
            let selected = &harness.state().selected;
            assert!(selected.contains("gobuild") && selected.contains("brew"));
            assert!(!selected.contains("images"), "Review items must not be auto-selected");
            assert!(!selected.contains("raw"), "informational items are not selectable");
            harness.get_by_label("Clean 2 · 20.6 GB");
            save(&mut harness, "results");
        }

        #[test]
        fn confirm_modal_warns_and_cancels() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().selected = ["images".to_owned(), "tm".to_owned()].into();
            harness.run();
            harness.get_by_label("Clean 2 · 32.3 GB").click();
            harness.run();
            harness.get_by_label("Clean 2 items?");
            harness.get_by_label_contains("2 items are marked Review");
            harness.get_by_label_contains("1 item needs administrator access");
            harness.get_by_label_contains("2 items are removed permanently, not moved to the Trash");
            assert!(harness.query_by_label_contains("first. Items of apps").is_none(), "no app to quit");
            save(&mut harness, "confirm");
            harness.get_by_label("Cancel").click();
            harness.run();
            assert!(harness.state().dialog.is_none());
            assert_eq!(harness.state().findings.len(), 5, "cancel must not remove anything");
        }

        #[test]
        fn ignored_items_are_never_cleaned_even_if_selected() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().ignored = ["gobuild".to_owned()].into();
            harness.state_mut().show_ignored = true;
            // A selection that still contains an ignored id (e.g. ignored after it was ticked).
            harness.state_mut().selected = ["gobuild".to_owned(), "brew".to_owned()].into();
            harness.run();
            let set: Vec<String> = harness.state().clean_set().iter().map(|f| f.id.clone()).collect();
            assert_eq!(set, ["brew"]);
            harness.get_by_label("Clean 1 · 1.8 GB").click();
            harness.run();
            harness.get_by_label("Clean 1 item?");
            let checkbox = harness.get_by_label("Select Go build cache");
            assert!(checkbox.accesskit_node().is_disabled(), "ignored rows cannot be ticked");
        }

        #[test]
        fn confirm_lists_items_hidden_by_the_filter() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().selected = ["images".to_owned(), "brew".to_owned()].into();
            harness.state_mut().category = Some(Category::DeveloperCaches);
            harness.run();
            harness.get_by_label("Clean 2 · 34.1 GB").click();
            harness.run();
            harness.get_by_label("Clean 2 items?");
            harness.get_by_label("Unused Docker images");
            harness.get_by_label_contains("1 of these is not shown by the current filter");
        }

        #[test]
        fn age_filter_hides_recent_and_undated_items() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            let now = format::now_unix();
            let mut findings = sample();
            findings[2].last_modified = Some(now - 40 * 86_400); // gobuild: 40 days
            findings[3].last_modified = Some(now - 86_400); // brew: yesterday
            harness.state_mut().findings = findings;
            harness.state_mut().phase = Phase::Idle;
            harness.run();
            harness.get_by_label("40 days ago");
            harness.get_by_label("1 day ago");
            harness.state_mut().older_than = Some(30);
            harness.run();
            let visible: Vec<String> =
                harness.state().visible().iter().map(|i| harness.state().findings[*i].id.clone()).collect();
            assert_eq!(visible, ["gobuild"], "recent and undated items are hidden");
            save(&mut harness, "age-filter");
        }

        #[test]
        fn ignored_items_are_hidden_from_results_totals_and_selection() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().selected = ["images".to_owned()].into();
            harness.state_mut().toggle_ignored("images");
            harness.run();
            assert!(harness.state().selected.is_empty(), "ignoring deselects");
            assert!(harness.query_by_label("Unused Docker images").is_none());
            harness.get_by_label("4 items · 20.6 GB+ reclaimable");
            harness.get_by_label("Select all").click();
            harness.run();
            assert!(!harness.state().selected.contains("images"));
            harness.get_by_label("Show ignored (1)").click();
            harness.run();
            harness.get_by_label("Unused Docker images");
            harness.get_by_label("ignored");
            harness.state_mut().toggle_ignored("images");
            assert!(harness.state().ignored.is_empty());
        }

        #[test]
        fn settings_are_loaded_and_saved_on_change() {
            let home = tempfile::tempdir().expect("tempdir");
            let code = home.path().join("code");
            std::fs::create_dir_all(&code).expect("mkdir");
            let path = home.path().join("config/settings.json");
            let store = SettingsStore::at(path.clone());
            store
                .save(&Settings {
                    project_roots: Some(vec![code.clone()]),
                    mode: Some(DeleteMode::Permanent),
                    older_than: Some(90),
                    ignored: ["x".to_owned()].into(),
                })
                .expect("seed");
            let home_path = home.path().to_path_buf();
            let mut harness = Harness::builder()
                .with_size(vec2(1200.0, 760.0))
                .build_eframe(move |cc| DiskdustApp::new(cc, Os::current().expect("os"), home_path, store));
            harness.run();
            let state = harness.state();
            assert_eq!(state.mode, DeleteMode::Permanent);
            assert_eq!(state.older_than, Some(90));
            assert_eq!(state.project_roots, vec![code.canonicalize().expect("canonical")]);
            assert!(state.ignored.contains("x"));
            harness.get_by_label("Move to Trash").click();
            harness.run();
            let saved = SettingsStore::at(path).load().settings;
            assert_eq!(saved.mode, Some(DeleteMode::Trash));
            assert_eq!(saved.older_than, Some(90));
        }

        #[test]
        fn unreadable_settings_are_backed_up_before_being_overwritten() {
            let home = tempfile::tempdir().expect("tempdir");
            let path = home.path().join("config/settings.json");
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            let original = br#"{"ignored": "not-a-list", "older_than": 30}"#;
            std::fs::write(&path, original).expect("write");
            let store = SettingsStore::at(path.clone());
            let home_path = home.path().to_path_buf();
            let mut harness = Harness::builder()
                .with_size(vec2(1200.0, 760.0))
                .build_eframe(move |cc| DiskdustApp::new(cc, Os::current().expect("os"), home_path, store));
            harness.run();
            assert_eq!(harness.state().older_than, Some(30), "readable fields are kept");
            assert!(harness.state().status.starts_with("Some settings could not be read"));
            harness.get_by_label("Delete permanently").click();
            harness.run();
            let backup = path.with_extension("json.bad");
            assert_eq!(std::fs::read(&backup).expect("backup kept"), original);
            let saved = SettingsStore::at(path).load();
            assert_eq!(saved.problem, None, "the new file is valid");
            assert_eq!(saved.settings.older_than, Some(30));
        }

        #[test]
        fn details_panel_shows_item_and_largest_folders() {
            let home = tempfile::tempdir().expect("tempdir");
            let home_path = home.path().canonicalize().expect("canonical");
            let dir = home_path.join("cache/big");
            for (name, len) in [("alpha", 300_000usize), ("beta", 10_000)] {
                std::fs::create_dir_all(dir.join(name)).expect("mkdir");
                std::fs::write(dir.join(name).join("f"), vec![0u8; len]).expect("write");
            }
            let mut item = finding("big", "Big cache", Some(310_000), Risk::Safe, Privilege::User);
            item.path = Some(dir.clone());
            item.action = Some(CleanupAction::RemovePath { path: dir, root: home_path.join("cache") });
            let mut harness = harness(&home_path);
            harness.state_mut().findings = vec![item];
            harness.state_mut().phase = Phase::Idle;
            harness.run();
            harness.get_by_label("Big cache").click();
            harness.run();
            assert_eq!(harness.state().details.as_deref(), Some("big"));
            harness.get_by_label("Moved to the Trash.");
            harness.get_by_label("Largest folders").click();
            for _ in 0..200 {
                harness.step();
                if matches!(harness.state().breakdown, Breakdown::Ready(..)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            harness.run();
            harness.get_by_label("alpha");
            harness.get_by_label("beta");
            save(&mut harness, "details");
            harness.get_by_label("Close").click();
            harness.run();
            assert!(harness.state().details.is_none());
        }

        #[test]
        fn free_space_and_history_window() {
            let home = tempfile::tempdir().expect("tempdir");
            let home_path = home.path().canonicalize().expect("canonical");
            let os = Os::current().expect("os");
            let entry = diskdust_core::audit::AuditEntry {
                timestamp: "2026-11-22T10:30:00Z".into(),
                run_id: "r".into(),
                finding_id: "go".into(),
                title: "Go build cache".into(),
                path: None,
                bytes: Some(18_800_000_000),
                action: CleanupAction::Run(KnownCommand::GoCleanBuildCache),
                mode: DeleteMode::Trash,
                elevated: false,
                ok: true,
                message: "Done".into(),
            };
            crate::session::default_audit_log(os, &home_path).append(&entry).expect("seed audit");
            let mut harness = harness(&home_path);
            harness.run();
            assert!(harness.state().disk.is_some());
            harness.get_by_label_contains(" free of ");
            harness.get_by_label("History").click();
            harness.run();
            harness.get_by_label("Go build cache");
            harness.get_by_label("2026-11-22 10:30");
            save(&mut harness, "history");
        }

        #[test]
        fn empty_trash_after_trash_mode_clean() {
            let home = tempfile::tempdir().expect("tempdir");
            let home_path = home.path().canonicalize().expect("canonical");
            let trash = match Os::current().expect("os") {
                Os::MacOs => home_path.join(".Trash"),
                Os::Linux => home_path.join(".local/share/Trash"),
            };
            std::fs::create_dir_all(trash.join("files")).expect("mkdir");
            std::fs::write(trash.join("files/old.bin"), vec![0u8; 2 * 1024 * 1024]).expect("write");
            let mut harness = harness(&home_path);
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().offer_empty_trash = true;
            harness.run();
            harness.get_by_label("Empty Trash…").click();
            harness.run();
            harness.get_by_label("Empty the Trash?");
            harness.get_by_label("Empty Trash").click();
            wait_until_idle(&mut harness);
            assert_eq!(std::fs::read_dir(&trash).expect("trash").count(), 0, "emptied");
            assert!(trash.is_dir(), "the Trash folder itself stays");
            assert!(!harness.state().offer_empty_trash);
            assert!(harness.state().status.starts_with("Cleaned 1 item, freed"), "{}", harness.state().status);
        }

        #[test]
        fn full_disk_access_banner_can_be_dismissed() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().full_disk_access = Some(false);
            harness.run();
            harness.get_by_label_contains("without Full Disk Access");
            harness.get_by_label("Open Privacy settings");
            save(&mut harness, "full-disk-access");
            harness.get_by_label("Dismiss").click();
            harness.run();
            assert!(harness.query_by_label_contains("without Full Disk Access").is_none());
            harness.state_mut().full_disk_access = Some(true);
            harness.run();
            assert!(harness.query_by_label_contains("without Full Disk Access").is_none());
        }

        #[test]
        fn rescan_clears_selection() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().selected = ["images".to_owned()].into();
            harness.run();
            harness.get_by_label("Rescan");
            // Hermetic: reset state as Rescan does, without scanning the test machine (real
            // docker / brew / xcrun calls are slow and non-deterministic on CI runners).
            harness.state_mut().begin_scan();
            assert!(harness.state().selected.is_empty());
            assert!(matches!(harness.state().phase, Phase::Scanning { .. }));
        }

        #[test]
        fn all_icons_have_glyphs() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.run();
            let font = egui::FontId::proportional(14.0);
            for icon in ALL_ICONS {
                assert!(harness.ctx.fonts_mut(|f| f.has_glyphs(&font, icon)), "missing glyph for {icon:?}");
            }
        }

        #[test]
        fn background_is_black() {
            let v = visuals();
            assert_eq!(v.panel_fill, Color32::BLACK);
            assert_ne!(v.extreme_bg_color, Color32::BLACK, "inputs must stand out from the background");
            assert_ne!(v.faint_bg_color, Color32::BLACK, "striped rows must stay visible");
        }

        #[test]
        fn select_all_selects_every_actionable_visible_item() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.run();
            harness.get_by_label("Select all").click();
            harness.run();
            let selected = &harness.state().selected;
            assert_eq!(selected.len(), 4);
            assert!(!selected.contains("raw"), "informational items are not selectable");
            harness.get_by_label("Clear").click();
            harness.run();
            assert!(harness.state().selected.is_empty());
            harness.state_mut().category = Some(Category::Containers);
            harness.run();
            harness.get_by_label("Select all").click();
            harness.run();
            assert_eq!(harness.state().selected, ["images".to_owned()].into(), "respects the category filter");
        }

        #[test]
        fn totals_exclude_informational_items_and_flag_unknown_sizes() {
            let home = tempfile::tempdir().expect("tempdir");
            let mut harness = harness(home.path());
            harness.state_mut().findings = sample();
            harness.state_mut().phase = Phase::Idle;
            harness.run();
            harness.get_by_label("52.9 GB+");
            harness.get_by_label("5 items · 52.9 GB+ reclaimable");
            // Containers: only the 32.3 GB of images, not the 64.4 GB info-only disk image.
            assert_eq!(harness.query_all_by_label("32.3 GB").count(), 2, "sidebar total + table row");
            assert!(harness.query_by_label("96.7 GB").is_none());
            assert!(harness.query_by_label("117 GB").is_none());
            // System holds only the snapshots, whose size is unknown: sidebar + table row.
            assert_eq!(harness.query_all_by_label("size unknown").count(), 2);
        }

        #[test]
        fn project_folders_and_activity_render() {
            let home = tempfile::tempdir().expect("tempdir");
            let code = home.path().join("code");
            std::fs::create_dir_all(&code).expect("mkdir");
            let mut harness = harness(home.path());
            harness.state_mut().project_roots = vec![code];
            harness.state_mut().log(true, "Go build cache — Done".to_owned());
            harness.state_mut().log(false, "Stale — permission denied".to_owned());
            harness.run();
            harness.get_by_label("Activity (2)").click();
            harness.run();
            harness.get_by_label_contains("permission denied");
            harness.get_by_label(ICON_REMOVE).click();
            harness.run();
            assert!(harness.state().project_roots.is_empty());
            save(&mut harness, "activity");
        }

        #[test]
        fn clean_counts_every_item() {
            let home = tempfile::tempdir().expect("tempdir");
            let home_path = home.path().canonicalize().expect("canonical");
            let root = home_path.join("cache");
            let mut items = Vec::new();
            for name in ["a", "b", "c"] {
                let dir = root.join(name);
                std::fs::create_dir_all(&dir).expect("mkdir");
                std::fs::write(dir.join("blob"), vec![0u8; 1000]).expect("write");
                let mut item = finding(name, name, Some(1000), Risk::Safe, Privilege::User);
                item.path = Some(dir.clone());
                item.action = Some(CleanupAction::RemovePath { path: dir, root: root.clone() });
                items.push(item);
            }
            let mut harness = harness(&home_path);
            harness.state_mut().findings = items;
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().mode = DeleteMode::Permanent;
            harness.run();
            harness.get_by_label("Select all").click();
            harness.run();
            harness.get_by_label_contains("Clean 3").click();
            harness.run();
            harness.get_by_label("Delete 3 items permanently").click();
            wait_until_idle(&mut harness);
            let status = &harness.state().status;
            assert!(status.starts_with("Cleaned 3 items, freed 3.0 kB"), "{status}");
            assert!(status.contains("(measured)"), "free-space change is measured: {status}");
            assert_eq!(std::fs::read_dir(&root).expect("read").count(), 0);
        }

        #[test]
        fn clean_flow_deletes_selected_item_and_logs_it() {
            let home = tempfile::tempdir().expect("tempdir");
            let home_path = home.path().canonicalize().expect("canonical");
            let target = home_path.join("cache/stale");
            std::fs::create_dir_all(&target).expect("mkdir");
            std::fs::write(target.join("blob"), vec![0u8; 4096]).expect("write");
            let mut item = finding("stale", "Stale cache", Some(4096), Risk::Safe, Privilege::User);
            item.path = Some(target.clone());
            item.action = Some(CleanupAction::RemovePath { path: target.clone(), root: home_path.join("cache") });
            let mut harness = harness(&home_path);
            harness.state_mut().findings = vec![item];
            harness.state_mut().phase = Phase::Idle;
            harness.state_mut().selected = ["stale".to_owned()].into();
            harness.run();
            harness.get_by_label("Delete permanently").click();
            harness.run();
            harness.get_by_label_contains("Clean 1").click();
            harness.run();
            harness.get_by_label_contains("cannot be undone");
            harness.get_by_label("Delete 1 item permanently").click();
            wait_until_idle(&mut harness);
            assert!(!target.exists(), "selected item must be removed");
            assert!(home_path.join("cache").exists(), "its parent must remain");
            assert!(harness.state().findings.is_empty());
            let status = &harness.state().status;
            assert!(status.starts_with("Cleaned 1 item, freed 4.1 kB"), "{status}");
            assert!(status.contains("(measured)"), "free-space change is measured: {status}");
            // Same resolution as the worker, so the test also passes when XDG_STATE_HOME is set.
            let log = diskdust_core::audit::AuditLog::default_location(
                &home_path,
                Os::current().expect("os"),
                std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            );
            let text = std::fs::read_to_string(log.path()).expect("audit log written");
            assert!(text.contains("\"ok\":true") && text.contains("Stale cache"));
            save(&mut harness, "after-clean");
        }
    }
}
