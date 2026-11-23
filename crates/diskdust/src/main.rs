//! diskdust: find and reclaim hidden disk space on macOS and Linux.
//!
//! - `diskdust` opens the desktop app.
//! - `diskdust scan [filters] [--json]` prints a read-only report in the terminal.
//! - `diskdust clean [filters] (--dry-run | --yes)` cleans matching items without the window.
//! - `diskdust helper <payload>` is the privileged helper the app launches through the OS
//!   authorization prompt; it is not meant to be run by hand.

mod app;
mod cli;
mod format;
mod schedule;
mod session;
mod settings;
mod worker;

use std::process::ExitCode;

use anyhow::Context as _;
use diskdust_core::clean::SystemTrash;
use diskdust_core::command::SystemRunner;
use diskdust_core::model::Os;
use diskdust_core::privilege::{self, HELPER_SUBCOMMAND};

/// Window/taskbar icon (the installers use the same artwork from `assets/`).
const APP_ICON: &[u8] = include_bytes!("../../../assets/icon-256.png");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(HELPER_SUBCOMMAND) {
        return helper(args.get(2).map_or("", String::as_str));
    }
    init_tracing();
    let result = match args.get(1).map(String::as_str) {
        None => run_gui(),
        Some("scan") => cli::scan(&args[2..]),
        Some("clean") => cli::clean(&args[2..]),
        Some("undo") => cli::undo(&args[2..]),
        Some("report") => cli::report(&args[2..]),
        Some("schedule") => cli::schedule(&args[2..]),
        Some("-h" | "--help") => {
            println!("{}", cli::USAGE);
            Ok(())
        }
        Some(other) => Err(anyhow::anyhow!("unknown command `{other}`\n\n{}", cli::USAGE)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("diskdust: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Privileged helper: executes validated admin actions and prints one JSON result per line.
fn helper(payload: &str) -> ExitCode {
    let Some(os) = Os::current() else {
        eprintln!("diskdust helper: unsupported platform");
        return ExitCode::from(2);
    };
    let runner = SystemRunner::trusted();
    match privilege::run_helper(payload, &privilege::admin_roots(os), &runner, &SystemTrash) {
        Ok(results) => {
            print!("{}", privilege::format_helper_output(&results));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("diskdust helper: {e}");
            ExitCode::from(2)
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("diskdust=info,diskdust_core=info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}

fn run_gui() -> anyhow::Result<()> {
    let os = Os::current().context("diskdust supports macOS and Linux only")?;
    let home = dirs::home_dir().context("cannot determine your home directory")?;
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("diskdust")
        .with_app_id("diskdust")
        .with_inner_size([1200.0, 780.0])
        .with_min_inner_size([900.0, 540.0]);
    match eframe::icon_data::from_png_bytes(APP_ICON) {
        Ok(icon) => viewport = viewport.with_icon(icon),
        Err(e) => tracing::warn!(error = %e, "could not decode the window icon"),
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "diskdust",
        options,
        Box::new(move |cc| {
            Ok(Box::new(app::DiskdustApp::new(cc, os, home, settings::SettingsStore::default_location())))
        }),
    )
    .map_err(|e| anyhow::anyhow!("failed to open the window: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_icon_decodes() {
        let icon = eframe::icon_data::from_png_bytes(APP_ICON).expect("valid png");
        assert_eq!((icon.width, icon.height), (256, 256));
    }
}
