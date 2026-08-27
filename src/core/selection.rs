//! Provider selection: the pure decision function at the heart of failover.
//!
//! This module deliberately contains no I/O, no locks and no clock reads.
//! Everything it needs — the current time included — is passed in. That is
//! what makes the switching policy exhaustively testable: the awkward cases
//! (a forced provider that is down, a primary that recovers mid-flap, a
//! backup that dies while the primary is still in its stability window) are
//! ordinary unit tests here instead of things you can only discover on a
//! production gateway at 3 a.m.
//!
//! # The policy, in one paragraph
//!
//! Leaving a broken uplink is urgent and unconditional: users are offline
//! *now*, so any healthy provider is better than the one we are on, and we
//! move immediately. Returning to a higher-priority uplink is the opposite —
//! nothing is broken, so there is no rush, and switching too eagerly is
//! exactly how a gateway ends up flapping and resetting every TCP
//! connection each time an ISP twitches. Failback therefore waits until the
//! better provider has been continuously healthy for a sustained window, and
//! that window grows if the link has proven unstable recently.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::time::Duration;

use crate::balancer::State;

/// Everything the decision needs to know about one provider.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderView {
    pub name: String,
    pub priority: u32,
    pub state: State,
    /// When this provider most recently *became* `Up`. `None` whenever it is
    /// not currently `Up`. Used to measure the failback stability window.
    pub up_since: Option<DateTime<Utc>>,
}

impl ProviderView {
    fn is_up(&self) -> bool {
        self.state == State::Up
    }

    /// Has it been continuously healthy for at least `window`?
    fn stable_for(&self, now: DateTime<Utc>, window: Duration) -> bool {
        match self.up_since {
            None => false,
            Some(since) => {
                let elapsed = now.signed_duration_since(since);
                elapsed >= ChronoDuration::from_std(window).unwrap_or(ChronoDuration::zero())
            }
        }
    }
}

/// Inputs to one selection decision.
#[derive(Debug, Clone)]
pub struct SelectionInput {
    pub now: DateTime<Utc>,
    /// Provider currently installed as the default route.
    pub current: Option<String>,
    /// Operator pin, if any.
    pub forced: Option<String>,
    pub providers: Vec<ProviderView>,
    /// How long a better provider must have been healthy before we fail
    /// back to it. Already adjusted for flap backoff by the caller.
    pub failback_stable: Duration,
}

/// What the balancer should do.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Current route is correct; do nothing.
    Keep,
    /// Install `to` as the default route.
    Switch { to: String, reason: String },
    /// A better provider exists but has not been stable long enough yet.
    /// Distinct from `Keep` so the daemon can log the countdown and the TUI
    /// can show "failback pending".
    WaitingForFailback {
        candidate: String,
        stable_for: Duration,
        required: Duration,
    },
    /// Nothing is healthy. The caller keeps whatever route is installed —
    /// a black-holing route is still better than no route at all, and the
    /// alternative would drop even the traffic that might still work.
    NoHealthyProvider,
}

/// Decide which provider should own the default route.
pub fn decide(input: &SelectionInput) -> Decision {
    let SelectionInput {
        now,
        current,
        forced,
        providers,
        failback_stable,
    } = input;

    // ── 1. Operator pin wins whenever it is actually usable. ────────────
    if let Some(pin) = forced {
        match providers.iter().find(|p| &p.name == pin) {
            Some(p) if p.is_up() => {
                return switch_or_keep(current.as_deref(), p, "operator override".to_string());
            }
            Some(_) => {
                // Pinned but unhealthy: serve the best healthy provider
                // meanwhile. The pin is not cleared — we snap back to it the
                // moment it recovers, which is what an operator expects from
                // a pin, as opposed to a one-shot switch.
                return match best_healthy(providers) {
                    Some(b) => switch_or_keep(
                        current.as_deref(),
                        b,
                        format!("forced provider '{pin}' is not healthy, using best available"),
                    ),
                    None => Decision::NoHealthyProvider,
                };
            }
            None => {
                // Pin names a provider that is not in the config. Should be
                // impossible (the control plane validates), but never let it
                // wedge selection.
                return match best_healthy(providers) {
                    Some(b) => switch_or_keep(
                        current.as_deref(),
                        b,
                        format!("forced provider '{pin}' does not exist, using best available"),
                    ),
                    None => Decision::NoHealthyProvider,
                };
            }
        }
    }

    // ── 2. Automatic selection: lowest priority number among healthy. ───
    let Some(best) = best_healthy(providers) else {
        return Decision::NoHealthyProvider;
    };

    let Some(cur_name) = current.as_deref() else {
        // Nothing installed yet — first healthy provider wins outright.
        return Decision::Switch {
            to: best.name.clone(),
            reason: "initial selection".to_string(),
        };
    };

    if cur_name == best.name {
        return Decision::Keep;
    }

    let cur = providers.iter().find(|p| p.name == cur_name);

    // ── 3. Escaping a broken provider is unconditional and immediate. ───
    //
    // No stability window, no dwell time. Whatever is healthy right now is
    // strictly better than what we are on, and every second of delay is a
    // second of downtime for every client behind this gateway.
    match cur {
        None => {
            return Decision::Switch {
                to: best.name.clone(),
                reason: format!("current provider '{cur_name}' is no longer configured"),
            };
        }
        Some(c) if !c.is_up() => {
            return Decision::Switch {
                to: best.name.clone(),
                reason: format!(
                    "'{cur_name}' is {} — switching to healthy '{}' (priority {})",
                    c.state.as_label(),
                    best.name,
                    best.priority
                ),
            };
        }
        Some(_) => {}
    }

    // ── 4. Failback: current is healthy, but a better one is available. ─
    //
    // This is the only path that waits. `best.priority < cur.priority` is
    // guaranteed here: `best` is the minimum over healthy providers and the
    // current one is healthy, so it was in that set.
    if best.stable_for(*now, *failback_stable) {
        Decision::Switch {
            to: best.name.clone(),
            reason: format!(
                "failback to higher-priority '{}' (priority {} < {}), healthy for {}s",
                best.name,
                best.priority,
                cur.map(|c| c.priority).unwrap_or(u32::MAX),
                elapsed_secs(*now, best.up_since)
            ),
        }
    } else {
        Decision::WaitingForFailback {
            candidate: best.name.clone(),
            stable_for: Duration::from_secs(elapsed_secs(*now, best.up_since)),
            required: *failback_stable,
        }
    }
}

/// Healthy provider with the lowest priority number. Ties are broken by
/// name so the choice is deterministic across restarts — config validation
/// rejects duplicate priorities, so this is only a belt-and-braces guard.
fn best_healthy(providers: &[ProviderView]) -> Option<&ProviderView> {
    providers.iter().filter(|p| p.is_up()).min_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.name.cmp(&b.name))
    })
}

fn switch_or_keep(current: Option<&str>, target: &ProviderView, reason: String) -> Decision {
    if current == Some(target.name.as_str()) {
        Decision::Keep
    } else {
        Decision::Switch {
            to: target.name.clone(),
            reason,
        }
    }
}

fn elapsed_secs(now: DateTime<Utc>, since: Option<DateTime<Utc>>) -> u64 {
    since
        .map(|s| now.signed_duration_since(s).num_seconds().max(0) as u64)
        .unwrap_or(0)
}

/// Flap damping.
///
/// Counts recent switches and stretches the failback window when a link has
/// proven unstable. Without this, a provider that comes up and dies every
/// 40 seconds drags the whole gateway with it — each switch flushes
/// conntrack and resets every live connection, so a flapping uplink is
/// *worse* for users than simply staying on the backup.
#[derive(Debug, Default)]
pub struct FlapTracker {
    switches: Vec<DateTime<Utc>>,
}

impl FlapTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_switch(&mut self, at: DateTime<Utc>) {
        self.switches.push(at);
        // Unbounded growth would be a slow leak on a long-lived daemon.
        if self.switches.len() > 256 {
            let drain = self.switches.len() - 256;
            self.switches.drain(..drain);
        }
    }

    pub fn switches_in_window(&self, now: DateTime<Utc>, window: Duration) -> u32 {
        let cutoff = now - ChronoDuration::from_std(window).unwrap_or(ChronoDuration::zero());
        self.switches.iter().filter(|t| **t >= cutoff).count() as u32
    }

    /// Effective failback window: `base`, doubled once for every switch past
    /// `threshold` inside `window`, capped at `max`.
    ///
    /// Example with base=30s, threshold=3: 3 switches → 30s, 4 → 60s,
    /// 5 → 120s, 6 → 240s. A stable link never leaves the base value, and
    /// the counter decays on its own as old switches fall out of the window.
    pub fn effective_failback(
        &self,
        now: DateTime<Utc>,
        base: Duration,
        threshold: u32,
        window: Duration,
        max: Duration,
    ) -> Duration {
        let recent = self.switches_in_window(now, window);
        if recent <= threshold {
            return base.min(max);
        }
        let excess = (recent - threshold).min(16); // 2^16 is already way past any cap
        base.checked_mul(1u32 << excess).unwrap_or(max).min(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn secs(n: i64) -> DateTime<Utc> {
        t0() + ChronoDuration::seconds(n)
    }

    fn up(name: &str, prio: u32, since: DateTime<Utc>) -> ProviderView {
        ProviderView {
            name: name.into(),
            priority: prio,
            state: State::Up,
            up_since: Some(since),
        }
    }

    fn down(name: &str, prio: u32) -> ProviderView {
        ProviderView {
            name: name.into(),
            priority: prio,
            state: State::Down,
            up_since: None,
        }
    }

    fn unknown(name: &str, prio: u32) -> ProviderView {
        ProviderView {
            name: name.into(),
            priority: prio,
            state: State::Unknown,
            up_since: None,
        }
    }

    fn input(
        now: DateTime<Utc>,
        current: Option<&str>,
        providers: Vec<ProviderView>,
    ) -> SelectionInput {
        SelectionInput {
            now,
            current: current.map(String::from),
            forced: None,
            providers,
            failback_stable: Duration::from_secs(30),
        }
    }

    fn switched_to(d: &Decision) -> Option<&str> {
        match d {
            Decision::Switch { to, .. } => Some(to.as_str()),
            _ => None,
        }
    }

    // ── basic selection ────────────────────────────────────────────────

    #[test]
    fn picks_lowest_priority_healthy_on_first_run() {
        let d = decide(&input(
            secs(0),
            None,
            vec![up("backup", 2, t0()), up("main", 0, t0())],
        ));
        assert_eq!(switched_to(&d), Some("main"));
    }

    /// The exact shape the operator asked about: priorities 0 and 2 with no
    /// 1 in between. The gap must not confuse ordering.
    #[test]
    fn priority_gap_zero_and_two_orders_correctly() {
        let providers = vec![up("isp-main", 0, t0()), up("isp-backup", 2, t0())];
        assert_eq!(
            switched_to(&decide(&input(secs(0), None, providers.clone()))),
            Some("isp-main")
        );

        // Primary dies → backup at priority 2 takes over even though no
        // provider occupies priority 1.
        let providers = vec![down("isp-main", 0), up("isp-backup", 2, secs(5))];
        assert_eq!(
            switched_to(&decide(&input(secs(10), Some("isp-main"), providers))),
            Some("isp-backup")
        );
    }

    #[test]
    fn keeps_current_when_it_is_already_best() {
        let d = decide(&input(
            secs(100),
            Some("main"),
            vec![up("main", 0, t0()), up("backup", 2, t0())],
        ));
        assert_eq!(d, Decision::Keep);
    }

    #[test]
    fn unknown_state_is_not_selectable() {
        // A provider that has not been probed yet must never be chosen —
        // "we don't know" is not "healthy".
        let d = decide(&input(secs(0), None, vec![unknown("main", 0)]));
        assert_eq!(d, Decision::NoHealthyProvider);

        let d = decide(&input(
            secs(0),
            None,
            vec![unknown("main", 0), up("backup", 2, t0())],
        ));
        assert_eq!(switched_to(&d), Some("backup"));
    }

    // ── the failure we are fixing ──────────────────────────────────────

    /// The whole point of the change. The primary is reachable at every
    /// layer that only asks "do packets come back", but the canary proved
    /// its content is being intercepted, so the health loop has it as Down.
    /// Selection must leave it immediately — no stability window applies to
    /// running away from a broken link.
    #[test]
    fn leaves_intercepted_primary_immediately() {
        let providers = vec![down("isp-main", 0), up("isp-backup", 2, secs(59))];
        // Only one second after the backup came up — well inside any
        // failback window — but that window governs coming *back*, never
        // leaving.
        let d = decide(&input(secs(60), Some("isp-main"), providers));
        assert_eq!(switched_to(&d), Some("isp-backup"));
        match d {
            Decision::Switch { reason, .. } => assert!(reason.contains("down"), "{reason}"),
            other => panic!("expected a switch, got {other:?}"),
        }
    }

    #[test]
    fn stays_on_backup_until_primary_is_stable() {
        // Primary recovered 10 s ago; window is 30 s.
        let providers = vec![up("main", 0, secs(50)), up("backup", 2, t0())];
        let d = decide(&input(secs(60), Some("backup"), providers.clone()));
        match d {
            Decision::WaitingForFailback {
                candidate,
                stable_for,
                required,
            } => {
                assert_eq!(candidate, "main");
                assert_eq!(stable_for, Duration::from_secs(10));
                assert_eq!(required, Duration::from_secs(30));
            }
            other => panic!("expected WaitingForFailback, got {other:?}"),
        }

        // At exactly the boundary it may switch.
        let d = decide(&input(secs(80), Some("backup"), providers.clone()));
        assert_eq!(switched_to(&d), Some("main"));

        // And well past it, certainly.
        let d = decide(&input(secs(200), Some("backup"), providers));
        assert_eq!(switched_to(&d), Some("main"));
    }

    /// A primary that keeps bouncing must not drag the gateway with it.
    /// Each time it drops, `up_since` resets, so the window restarts and we
    /// simply never fail back while it is unstable.
    #[test]
    fn flapping_primary_never_wins_the_failback_race() {
        for restart in [50, 70, 90, 110] {
            let providers = vec![up("main", 0, secs(restart)), up("backup", 2, t0())];
            // Always evaluated 10 s after the latest recovery.
            let d = decide(&input(secs(restart + 10), Some("backup"), providers));
            assert!(
                matches!(d, Decision::WaitingForFailback { .. }),
                "should still be waiting after restart at {restart}s, got {d:?}"
            );
        }
    }

    #[test]
    fn no_healthy_provider_keeps_the_existing_route() {
        let d = decide(&input(
            secs(10),
            Some("main"),
            vec![down("main", 0), down("backup", 2)],
        ));
        assert_eq!(d, Decision::NoHealthyProvider);

        // Also on a cold start with nothing up yet.
        let d = decide(&input(secs(0), None, vec![down("main", 0)]));
        assert_eq!(d, Decision::NoHealthyProvider);
    }

    #[test]
    fn backup_dying_while_primary_waits_moves_to_primary_at_once() {
        // Backup (current) fails before the primary finished its window.
        // Escaping wins over waiting.
        let providers = vec![up("main", 0, secs(55)), down("backup", 2)];
        let d = decide(&input(secs(60), Some("backup"), providers));
        assert_eq!(switched_to(&d), Some("main"));
    }

    #[test]
    fn current_provider_removed_from_config_triggers_switch() {
        let providers = vec![up("main", 0, t0())];
        let d = decide(&input(secs(10), Some("deleted-isp"), providers));
        assert_eq!(switched_to(&d), Some("main"));
    }

    // ── operator pin ───────────────────────────────────────────────────

    #[test]
    fn pin_overrides_priority_when_healthy() {
        let mut i = input(
            secs(10),
            Some("main"),
            vec![up("main", 0, t0()), up("backup", 2, t0())],
        );
        i.forced = Some("backup".into());
        assert_eq!(switched_to(&decide(&i)), Some("backup"));
    }

    #[test]
    fn pin_does_not_wait_for_a_stability_window() {
        // Operator intent is explicit; making them wait 30 s would be wrong.
        let mut i = input(
            secs(10),
            Some("backup"),
            vec![up("main", 0, secs(9)), up("backup", 2, t0())],
        );
        i.forced = Some("main".into());
        assert_eq!(switched_to(&decide(&i)), Some("main"));
    }

    #[test]
    fn pinned_but_down_falls_back_and_snaps_back_on_recovery() {
        // Pinned provider is down: serve the best healthy one meanwhile.
        let mut i = input(
            secs(10),
            Some("main"),
            vec![down("main", 0), up("backup", 2, t0())],
        );
        i.forced = Some("main".into());
        let d = decide(&i);
        assert_eq!(switched_to(&d), Some("backup"));
        match d {
            Decision::Switch { reason, .. } => assert!(reason.contains("not healthy"), "{reason}"),
            other => panic!("expected switch, got {other:?}"),
        }

        // It recovers → snap straight back to the pin, no window.
        let mut i = input(
            secs(20),
            Some("backup"),
            vec![up("main", 0, secs(19)), up("backup", 2, t0())],
        );
        i.forced = Some("main".into());
        assert_eq!(switched_to(&decide(&i)), Some("main"));
    }

    #[test]
    fn pin_already_active_is_a_keep_not_a_reswitch() {
        let mut i = input(
            secs(10),
            Some("backup"),
            vec![up("main", 0, t0()), up("backup", 2, t0())],
        );
        i.forced = Some("backup".into());
        assert_eq!(decide(&i), Decision::Keep);
    }

    #[test]
    fn pin_to_unknown_name_still_serves_traffic() {
        let mut i = input(secs(10), None, vec![up("main", 0, t0())]);
        i.forced = Some("typo-isp".into());
        assert_eq!(switched_to(&decide(&i)), Some("main"));
    }

    #[test]
    fn pin_down_and_nothing_healthy_reports_no_provider() {
        let mut i = input(secs(10), Some("main"), vec![down("main", 0)]);
        i.forced = Some("main".into());
        assert_eq!(decide(&i), Decision::NoHealthyProvider);
    }

    // ── flap tracking ──────────────────────────────────────────────────

    #[test]
    fn flap_tracker_counts_only_inside_the_window() {
        let mut f = FlapTracker::new();
        f.record_switch(secs(0));
        f.record_switch(secs(100));
        f.record_switch(secs(200));
        assert_eq!(f.switches_in_window(secs(250), Duration::from_secs(600)), 3);
        // Older ones age out.
        assert_eq!(f.switches_in_window(secs(250), Duration::from_secs(100)), 1);
        assert_eq!(f.switches_in_window(secs(1000), Duration::from_secs(60)), 0);
    }

    #[test]
    fn failback_window_grows_with_instability_and_is_capped() {
        let base = Duration::from_secs(30);
        let window = Duration::from_secs(600);
        let max = Duration::from_secs(900);
        let mut f = FlapTracker::new();

        // Quiet link: base window.
        assert_eq!(f.effective_failback(secs(0), base, 3, window, max), base);

        for i in 0..3 {
            f.record_switch(secs(i));
        }
        // At the threshold, still base.
        assert_eq!(f.effective_failback(secs(10), base, 3, window, max), base);

        f.record_switch(secs(11));
        assert_eq!(
            f.effective_failback(secs(12), base, 3, window, max),
            Duration::from_secs(60)
        );

        f.record_switch(secs(13));
        assert_eq!(
            f.effective_failback(secs(14), base, 3, window, max),
            Duration::from_secs(120)
        );

        // Runaway flapping saturates at the cap rather than overflowing.
        for i in 15..40 {
            f.record_switch(secs(i));
        }
        assert_eq!(f.effective_failback(secs(41), base, 3, window, max), max);
    }

    #[test]
    fn flap_penalty_decays_once_the_link_settles() {
        let base = Duration::from_secs(30);
        let window = Duration::from_secs(600);
        let max = Duration::from_secs(900);
        let mut f = FlapTracker::new();
        for i in 0..8 {
            f.record_switch(secs(i));
        }
        assert!(f.effective_failback(secs(10), base, 3, window, max) > base);
        // An hour later those switches are outside the window: back to base.
        assert_eq!(f.effective_failback(secs(3600), base, 3, window, max), base);
    }

    #[test]
    fn flap_tracker_does_not_grow_without_bound() {
        let mut f = FlapTracker::new();
        for i in 0..5000 {
            f.record_switch(secs(i));
        }
        assert!(
            f.switches.len() <= 256,
            "leaked {} entries",
            f.switches.len()
        );
    }

    #[test]
    fn effective_failback_never_exceeds_max_even_with_a_large_base() {
        let f = FlapTracker::new();
        let huge = Duration::from_secs(u64::MAX / 2);
        let max = Duration::from_secs(900);
        assert_eq!(
            f.effective_failback(secs(0), huge, 3, Duration::from_secs(600), max),
            max
        );
    }
}
