//! Human-readable formatting.

use std::time::Duration;

/// Formats bytes with decimal (SI) units, matching how macOS Finder and Docker report sizes.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut value = n as f64;
    let mut unit = "B";
    for next in UNITS {
        if value < 1000.0 {
            break;
        }
        value /= 1000.0;
        unit = next;
    }
    if value >= 100.0 { format!("{value:.0} {unit}") } else { format!("{value:.1} {unit}") }
}

/// Formats an optional size, using "size unknown" when absent.
pub fn maybe_bytes(n: Option<u64>) -> String {
    n.map_or_else(|| "size unknown".to_owned(), bytes)
}

/// Reclaimable size where some items may have an unknown size: "4.2 GB", "4.2 GB+", "size unknown".
pub fn reclaimable(known: u64, has_unknown: bool) -> String {
    match (known, has_unknown) {
        (0, true) => "size unknown".to_owned(),
        (b, true) => format!("{}+", bytes(b)),
        (b, false) => bytes(b),
    }
}

/// "1 item", "3 items".
pub fn items(n: usize) -> String {
    if n == 1 { "1 item".to_owned() } else { format!("{n} items") }
}

/// "1 item is", "3 items are".
pub fn items_are(n: usize) -> String {
    if n == 1 { "1 item is".to_owned() } else { format!("{n} items are") }
}

pub fn duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 { format!("{secs:.1} s") } else { format!("{}m {:02}s", d.as_secs() / 60, d.as_secs() % 60) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_000), "1.0 kB");
        assert_eq!(bytes(1_536_000), "1.5 MB");
        assert_eq!(bytes(31_300_000_000), "31.3 GB");
        assert_eq!(bytes(250_000_000_000), "250 GB");
        assert_eq!(bytes(1_200_000_000_000), "1.2 TB");
        assert_eq!(bytes(u64::MAX), "18447 PB");
    }

    #[test]
    fn reclaimable_marks_unknown_sizes() {
        assert_eq!(reclaimable(0, true), "size unknown");
        assert_eq!(reclaimable(2_000, true), "2.0 kB+");
        assert_eq!(reclaimable(0, false), "0 B");
    }

    #[test]
    fn pluralizes_items() {
        assert_eq!(items(1), "1 item");
        assert_eq!(items(0), "0 items");
        assert_eq!(items_are(1), "1 item is");
        assert_eq!(items_are(4), "4 items are");
    }

    #[test]
    fn formats_optional_and_durations() {
        assert_eq!(maybe_bytes(None), "size unknown");
        assert_eq!(maybe_bytes(Some(2_000)), "2.0 kB");
        assert_eq!(duration(Duration::from_millis(4_250)), "4.2 s");
        assert_eq!(duration(Duration::from_secs(125)), "2m 05s");
    }
}
