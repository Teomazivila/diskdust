//! diskdust engine: discovers reclaimable disk space on macOS and Linux and removes it safely.
//!
//! - [`scanners`] discover [`model::Finding`]s (read-only).
//! - [`scan::run_scan`] runs scanners in parallel and merges their results.
//! - [`clean::Cleaner`] executes cleanup actions after re-validating them with [`safety`].
//! - [`privilege`] implements the privileged helper protocol for admin-only items.

pub mod access;
pub mod audit;
pub mod clean;
pub mod command;
pub mod disk;
pub mod model;
pub mod privilege;
pub mod safety;
pub mod scan;
pub mod scanners;
pub mod size;
pub mod units;
