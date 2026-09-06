//! Human-readable formatting, in one place.
//!
//! The dashboard, the CLI reports and the stats summary all render the same
//! quantities, and for a while each had its own copy of the conversion — with
//! its own idea of whether a kilobyte was 1000 or 1024, and whether a rate
//! was written in bits or bytes. Sizes here are binary (KiB, MiB) because
//! that is what a byte counter measures; rates are decimal bits per second
//! because that is what a link is sold in.

use chrono::{DateTime, Utc};

/// A byte count: `1.44 MiB`.
pub fn bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0usize;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[u])
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

/// A rate given in *bits* per second: `12.4 Mbit/s`.
pub fn rate(bits_per_sec: f64) -> String {
    const UNITS: &[&str] = &["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    let mut v = bits_per_sec.max(0.0);
    let mut u = 0usize;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

/// A rate given in *bytes* per second — what byte counters produce.
pub fn rate_from_bytes(bytes_per_sec: f64) -> String {
    rate(bytes_per_sec * 8.0)
}

/// A span of time, coarse enough to read at a glance: `3d 04h12m`, `12m30s`.
pub fn duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h{minutes:02}m")
    } else if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

/// A large count, abbreviated: `1.2k`, `3.4M`.
pub fn count(n: u64) -> String {
    if n < 1_000 {
        format!("{n}")
    } else if n < 1_000_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else if n < 1_000_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else {
        format!("{:.2}G", n as f64 / 1_000_000_000.0)
    }
}

/// How long ago something happened: `now`, `40s ago`, `3h12m ago`.
pub fn ago(then: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (now - then).num_seconds();
    if secs < 0 {
        // A clock that has just been stepped backwards. "In the future" is
        // not useful to anyone; treat it as the present.
        return "now".into();
    }
    if secs < 10 {
        return "now".into();
    }
    format!("{} ago", duration(secs as u64))
}

/// A local wall-clock stamp for a table: `09-05 14:22`.
pub fn stamp(t: DateTime<Utc>) -> String {
    t.with_timezone(&chrono::Local)
        .format("%m-%d %H:%M")
        .to_string()
}

/// A local wall-clock stamp including seconds.
pub fn stamp_secs(t: DateTime<Utc>) -> String {
    t.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_are_binary_and_readable() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.00 KiB");
        assert_eq!(bytes(1_572_864), "1.50 MiB");
        // The largest unit saturates rather than running off the end.
        assert!(bytes(u64::MAX).ends_with("PiB"));
    }

    #[test]
    fn rates_are_decimal_bits() {
        assert_eq!(rate(0.0), "0.0 bit/s");
        assert_eq!(rate(1_000.0), "1.0 kbit/s");
        assert_eq!(rate(12_400_000.0), "12.4 Mbit/s");
        // A byte counter reads eight times lower than the link speed.
        assert_eq!(rate_from_bytes(125_000.0), "1.0 Mbit/s");
        // A negative rate is a bug upstream, not something to render.
        assert_eq!(rate(-5.0), "0.0 bit/s");
    }

    #[test]
    fn durations_shorten_as_they_grow() {
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(90), "1m30s");
        assert_eq!(duration(3_600), "1h00m");
        assert_eq!(duration(93_784), "1d 2h03m");
    }

    #[test]
    fn counts_abbreviate() {
        assert_eq!(count(999), "999");
        assert_eq!(count(1_500), "1.5k");
        assert_eq!(count(2_500_000), "2.5M");
        assert_eq!(count(3_000_000_000), "3.00G");
    }

    #[test]
    fn ago_handles_the_present_and_a_stepped_clock() {
        let now = Utc::now();
        assert_eq!(ago(now, now), "now");
        assert_eq!(ago(now + chrono::Duration::seconds(30), now), "now");
        assert_eq!(ago(now - chrono::Duration::seconds(120), now), "2m00s ago");
    }
}
