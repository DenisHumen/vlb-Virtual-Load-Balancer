//! Keeping conditions that are re-detected every probe round out of the log
//! once they stop being news.
//!
//! The probes run every few seconds, and a provider that is down stays down
//! for hours. Logging the verdict of every round turns the journal into a
//! wall of identical lines — tens of thousands a day — in which the one line
//! that matters (the uplink that just died, the switch that just happened)
//! is impossible to find. The rule here: say it once when it starts, say it
//! again when it changes, summarise it now and then while it lasts, and say
//! when it is over. Everything in between is DEBUG.
//!
//! Time is passed in, never read, so the rules are testable to the second.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How often a condition that persists is summarised.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(15 * 60);

/// What to log for one failed round of one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureLine {
    /// News: this layer started failing (or failed again after a long quiet
    /// spell). Log it in full.
    Report,
    /// Still failing, and the last line about it is old: `checks` failed
    /// rounds over `over`.
    Summary { checks: u32, over: Duration },
    /// Nothing new. DEBUG at most.
    Repeat,
}

/// One provider's failures, by layer.
///
/// Keyed by layer rather than by the full detail text: the detail carries
/// numbers (a latency, a measured rate, "2/3 targets") that differ from
/// round to round without anything having changed.
///
/// A failure counts as the same trouble while it keeps recurring within
/// [`SUMMARY_EVERY`] — so an uplink that flaps between passing and failing
/// every few rounds is one ongoing problem, summarised, not a fresh warning
/// each time it fails again.
#[derive(Debug, Default)]
pub struct FailureLog {
    layers: HashMap<&'static str, LayerLog>,
}

#[derive(Debug)]
struct LayerLog {
    /// When the last line about this layer was logged.
    last_line: Instant,
    /// Failed rounds since then, not counting the one that logged it.
    since_line: u32,
    /// The most recent failed round.
    last_failure: Instant,
}

impl FailureLog {
    pub fn failed(&mut self, layer: &'static str, now: Instant) -> FailureLine {
        let Some(l) = self.layers.get_mut(layer) else {
            self.layers.insert(
                layer,
                LayerLog {
                    last_line: now,
                    since_line: 0,
                    last_failure: now,
                },
            );
            return FailureLine::Report;
        };
        let quiet_for = now.saturating_duration_since(l.last_failure);
        l.last_failure = now;
        if quiet_for >= SUMMARY_EVERY {
            // It had stopped long enough ago that this is a new episode.
            l.last_line = now;
            l.since_line = 0;
            return FailureLine::Report;
        }
        let over = now.saturating_duration_since(l.last_line);
        if over >= SUMMARY_EVERY {
            let checks = l.since_line + 1;
            l.last_line = now;
            l.since_line = 0;
            return FailureLine::Summary { checks, over };
        }
        l.since_line += 1;
        FailureLine::Repeat
    }
}

/// What to log about a condition that is either on or off each round —
/// "no provider is healthy", for instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutageLine {
    Started,
    /// Still going, `lasted` so far.
    Reminder {
        lasted: Duration,
    },
    /// Still going, nothing to add.
    Quiet,
    /// It is over, after `lasted`.
    Ended {
        lasted: Duration,
    },
    /// It was not happening and still is not.
    Idle,
}

#[derive(Debug, Default)]
pub struct OutageLog {
    since: Option<Instant>,
    last_line: Option<Instant>,
}

impl OutageLog {
    pub fn observe(&mut self, happening: bool, now: Instant) -> OutageLine {
        match (self.since, happening) {
            (None, false) => OutageLine::Idle,
            (None, true) => {
                self.since = Some(now);
                self.last_line = Some(now);
                OutageLine::Started
            }
            (Some(since), false) => {
                self.since = None;
                self.last_line = None;
                OutageLine::Ended {
                    lasted: now.saturating_duration_since(since),
                }
            }
            (Some(since), true) => {
                let last = self.last_line.unwrap_or(since);
                if now.saturating_duration_since(last) >= SUMMARY_EVERY {
                    self.last_line = Some(now);
                    OutageLine::Reminder {
                        lasted: now.saturating_duration_since(since),
                    }
                } else {
                    OutageLine::Quiet
                }
            }
        }
    }
}

/// A duration the way an operator reads it in a log line: `45s`, `12m`,
/// `3h 05m`.
pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=89 => format!("{s}s"),
        90..=5399 => format!("{}m", (s + 30) / 60),
        _ => format!("{}h {:02}m", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICK: Duration = Duration::from_secs(10);

    /// A provider that stays down for the same reason: one full report, then
    /// a summary every fifteen minutes with the number of checks in it —
    /// instead of 90 warnings in those fifteen minutes.
    #[test]
    fn a_steady_failure_is_reported_once_then_summarised() {
        let t0 = Instant::now();
        let mut log = FailureLog::default();
        let mut lines = Vec::new();
        for i in 0..=180u32 {
            let line = log.failed("internet", t0 + TICK * i);
            if line != FailureLine::Repeat {
                lines.push((i, line));
            }
        }
        assert_eq!(
            lines,
            vec![
                (0, FailureLine::Report),
                (
                    90,
                    FailureLine::Summary {
                        checks: 90,
                        over: SUMMARY_EVERY
                    }
                ),
                (
                    180,
                    FailureLine::Summary {
                        checks: 90,
                        over: SUMMARY_EVERY
                    }
                ),
            ]
        );
    }

    /// A different layer failing is a change of state and is reported at
    /// once, even while the first one is being summarised.
    #[test]
    fn a_new_cause_is_news() {
        let t0 = Instant::now();
        let mut log = FailureLog::default();
        assert_eq!(log.failed("internet", t0), FailureLine::Report);
        assert_eq!(log.failed("internet", t0 + TICK), FailureLine::Repeat);
        assert_eq!(log.failed("dns", t0 + TICK * 2), FailureLine::Report);
        assert_eq!(log.failed("dns", t0 + TICK * 3), FailureLine::Repeat);
        assert_eq!(log.failed("internet", t0 + TICK * 4), FailureLine::Repeat);
    }

    /// Failing every few rounds is one ongoing problem; failing again after
    /// a long quiet spell is a new one.
    #[test]
    fn flapping_is_one_episode_and_a_long_quiet_spell_ends_it() {
        let t0 = Instant::now();
        let mut log = FailureLog::default();
        assert_eq!(log.failed("canary", t0), FailureLine::Report);
        // Passes in between (not reported to the log at all), fails again.
        assert_eq!(log.failed("canary", t0 + TICK * 5), FailureLine::Repeat);
        assert_eq!(log.failed("canary", t0 + TICK * 10), FailureLine::Repeat);
        // Quiet for longer than the summary interval: news again.
        let later = t0 + TICK * 10 + SUMMARY_EVERY;
        assert_eq!(log.failed("canary", later), FailureLine::Report);
        assert_eq!(log.failed("canary", later + TICK), FailureLine::Repeat);
    }

    /// "No healthy providers" is re-detected after every probe of every
    /// provider — dozens of times a minute. One line when it starts, a
    /// reminder every fifteen minutes, one line with the duration when it
    /// ends.
    #[test]
    fn an_outage_is_announced_reminded_and_closed() {
        let t0 = Instant::now();
        let mut log = OutageLog::default();
        assert_eq!(log.observe(false, t0), OutageLine::Idle);
        assert_eq!(log.observe(true, t0), OutageLine::Started);
        let mut reminders = 0;
        for i in 1..=200u32 {
            match log.observe(true, t0 + Duration::from_secs(5) * i) {
                OutageLine::Quiet => {}
                OutageLine::Reminder { lasted } => {
                    reminders += 1;
                    assert_eq!(lasted, SUMMARY_EVERY * reminders);
                }
                other => panic!("round {i}: {other:?}"),
            }
        }
        // 1000 s: one reminder at 900 s.
        assert_eq!(reminders, 1);
        assert_eq!(
            log.observe(false, t0 + Duration::from_secs(1010)),
            OutageLine::Ended {
                lasted: Duration::from_secs(1010)
            }
        );
        assert_eq!(
            log.observe(false, t0 + Duration::from_secs(1020)),
            OutageLine::Idle
        );
        assert_eq!(
            log.observe(true, t0 + Duration::from_secs(1030)),
            OutageLine::Started
        );
    }

    #[test]
    fn durations_read_like_a_person_wrote_them() {
        assert_eq!(human(Duration::from_secs(45)), "45s");
        assert_eq!(human(Duration::from_secs(12 * 60)), "12m");
        assert_eq!(human(Duration::from_secs(3 * 3600 + 5 * 60)), "3h 05m");
    }
}
