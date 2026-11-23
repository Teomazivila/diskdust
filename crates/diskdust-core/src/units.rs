//! Parsers for human-readable sizes emitted by external tools.

/// Parses Docker's human sizes (`"31.3GB (88%)"`, `"49.15kB"`, `"0B"`).
///
/// Docker formats sizes with `go-units.HumanSize`, which uses decimal (SI) multipliers.
/// A trailing percentage in parentheses is ignored.
pub fn parse_docker_size(raw: &str) -> Option<u64> {
    let value = raw.split_whitespace().next()?;
    let split = value.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (number, unit) = value.split_at(split);
    let multiplier: u64 = match unit {
        "B" => 1,
        "kB" | "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "PB" => 1_000_000_000_000_000,
        _ => return None,
    };
    to_bytes(number, multiplier)
}

/// Extracts the space Docker actually reclaimed from the summary line of a prune command:
/// `"Total reclaimed space: 29.53GB"` (image/container/volume prune) or `"Total:\t26.48GB"`
/// (builder prune).
pub fn parse_docker_reclaimed(line: &str) -> Option<u64> {
    let line = line.trim();
    let rest = line.strip_prefix("Total reclaimed space:").or_else(|| line.strip_prefix("Total:"))?;
    parse_docker_size(rest.trim())
}

/// Homebrew's own estimate from `brew cleanup --dry-run`: the line
/// `==> This operation would free approximately 2.2GB of disk space.` Homebrew formats sizes in
/// decimal units (`B`, `KB`, `MB`, `GB`), the same convention [`parse_docker_size`] reads.
pub fn parse_brew_estimate(output: &str) -> Option<u64> {
    output.lines().find_map(|line| {
        let rest = line.split_once("would free approximately ")?.1;
        parse_docker_size(rest.split_whitespace().next()?)
    })
}

/// Parses the output of `journalctl --disk-usage`, e.g.
/// `"Archived and active journals take up 1.2G in the file system."`.
///
/// journalctl uses binary (IEC) multipliers with single-letter suffixes.
pub fn parse_journal_usage(output: &str) -> Option<u64> {
    let mut words = output.split_whitespace();
    words.find(|w| *w == "up")?;
    let value = words.next()?;
    let split = value.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let multiplier: u64 = match unit {
        "" | "B" => 1,
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => return None,
    };
    to_bytes(number, multiplier)
}

/// Formats bytes with decimal (SI) units, matching how macOS Finder and Docker report sizes.
pub fn format_bytes(n: u64) -> String {
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

fn to_bytes(number: &str, multiplier: u64) -> Option<u64> {
    let parsed: f64 = number.parse().ok()?;
    if !parsed.is_finite() || parsed < 0.0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let bytes = (parsed * multiplier as f64).round();
    if bytes > 18_000_000_000_000_000_000.0 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_sizes_from_real_output() {
        assert_eq!(parse_docker_size("31.3GB (88%)"), Some(31_300_000_000));
        assert_eq!(parse_docker_size("12.85GB"), Some(12_850_000_000));
        assert_eq!(parse_docker_size("4.408GB (98%)"), Some(4_408_000_000));
        assert_eq!(parse_docker_size("49.15kB"), Some(49_150));
        assert_eq!(parse_docker_size("0B (0%)"), Some(0));
        assert_eq!(parse_docker_size("0B"), Some(0));
        assert_eq!(parse_docker_size("1.5TB"), Some(1_500_000_000_000));
        assert_eq!(parse_docker_size("2MB"), Some(2_000_000));
    }

    #[test]
    fn docker_size_rejects_garbage() {
        assert_eq!(parse_docker_size(""), None);
        assert_eq!(parse_docker_size("GB"), None);
        assert_eq!(parse_docker_size("12"), None);
        assert_eq!(parse_docker_size("12XB"), None);
        assert_eq!(parse_docker_size("1.2.3GB"), None);
    }

    #[test]
    fn docker_reclaimed_from_real_prune_output() {
        assert_eq!(parse_docker_reclaimed("Total reclaimed space: 29.53GB"), Some(29_530_000_000));
        assert_eq!(parse_docker_reclaimed("Total:\t26.48GB"), Some(26_480_000_000));
        assert_eq!(parse_docker_reclaimed("  Total reclaimed space: 0B\n"), Some(0));
        assert_eq!(parse_docker_reclaimed("Deleted Images:"), None);
        assert_eq!(parse_docker_reclaimed("Total: lots"), None);
    }

    #[test]
    fn brew_estimate_from_real_dry_run() {
        let out = "Would remove: /opt/homebrew/Library/Homebrew/vendor/portable-ruby/4.0.7 (1,707 files, 34.6MB)\n\
                   ==> This operation would free approximately 2.2GB of disk space.\n";
        assert_eq!(parse_brew_estimate(out), Some(2_200_000_000));
        assert_eq!(
            parse_brew_estimate("==> This operation would free approximately 512KB of disk space."),
            Some(512_000)
        );
        assert_eq!(
            parse_brew_estimate("==> This operation would free approximately 3MB of disk space."),
            Some(3_000_000)
        );
        assert_eq!(parse_brew_estimate(""), None);
        assert_eq!(parse_brew_estimate("would free approximately lots"), None);
    }

    #[test]
    fn journal_usage_parses_binary_units() {
        assert_eq!(
            parse_journal_usage("Archived and active journals take up 1.5G in the file system."),
            Some(1_610_612_736)
        );
        assert_eq!(
            parse_journal_usage("Archived and active journals take up 24.0M in the file system.\n"),
            Some(25_165_824)
        );
        assert_eq!(parse_journal_usage("Journals take up 512K in the file system."), Some(524_288));
        assert_eq!(parse_journal_usage("Journals take up 0B in the file system."), Some(0));
        assert_eq!(parse_journal_usage("Journals take up 100 in the file system."), Some(100));
    }

    #[test]
    fn journal_usage_rejects_unexpected_output() {
        assert_eq!(parse_journal_usage("No journal files were found."), None);
        assert_eq!(parse_journal_usage("take up 1.5Q in"), None);
        assert_eq!(parse_journal_usage("take up"), None);
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1.0 kB");
        assert_eq!(format_bytes(1_536_000), "1.5 MB");
        assert_eq!(format_bytes(31_300_000_000), "31.3 GB");
        assert_eq!(format_bytes(250_000_000_000), "250 GB");
        assert_eq!(format_bytes(1_200_000_000_000), "1.2 TB");
        assert_eq!(format_bytes(u64::MAX), "18447 PB");
    }

    #[test]
    fn rejects_absurd_numbers() {
        assert_eq!(to_bytes("NaN", 1), None);
        assert_eq!(to_bytes("inf", 1), None);
        assert_eq!(to_bytes("-1", 1), None);
        assert_eq!(to_bytes("1e30", 1), None);
    }
}
