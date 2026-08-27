use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::canary::{CanaryTarget, ContentExpectation, Quorum, parse_sha256};
use crate::http::Url;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub canary: CanaryConfig,
    #[serde(default)]
    pub failover: FailoverConfig,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub control: ControlConfig,
    #[serde(default)]
    pub traffic: TrafficConfig,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(default)]
    pub update: UpdateConfig,
    pub providers: Vec<Provider>,
}

// ─────────────────────────────────────────────────────────────────────────
// Content canary
// ─────────────────────────────────────────────────────────────────────────

/// Content-authenticity probing.
///
/// This is the layer that catches an uplink which is *reachable but
/// intercepted* — the unpaid-account case where the ISP answers every DNS
/// query with its portal and every HTTP request with a payment page. Purely
/// reachability-based checks (ping, "did DNS reply at all") cannot see it,
/// because the interceptor answers all of them happily. See
/// [`crate::canary`] for the full reasoning.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How often to run the canary, per provider. Deliberately slower than
    /// the ICMP tick: a TLS fetch is far more expensive than a ping, and
    /// content interception does not come and go between seconds.
    #[serde(default = "default_canary_interval")]
    pub interval_secs: u64,
    /// Per-target budget covering DNS, TCP, TLS and the HTTP exchange.
    #[serde(default = "default_canary_timeout_ms")]
    pub timeout_ms: u64,
    /// How many targets must verify: `any`, `majority` (default) or `all`.
    ///
    /// `majority` is the right default: it tolerates one endpoint being
    /// down or blocked in your region without failing over, while an
    /// interceptor — which necessarily breaks all of them — still trips it.
    #[serde(default = "default_quorum")]
    pub quorum: String,
    /// Consecutive canary rounds that must fail before the provider is
    /// marked unhealthy. Ignored when content came back *tampered*: that is
    /// proof, not a symptom, and acts on the first observation.
    #[serde(default = "default_canary_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_canary_targets")]
    pub targets: Vec<CanaryTargetConfig>,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_canary_interval(),
            timeout_ms: default_canary_timeout_ms(),
            quorum: default_quorum(),
            failure_threshold: default_canary_failure_threshold(),
            user_agent: default_user_agent(),
            targets: default_canary_targets(),
        }
    }
}

fn default_canary_interval() -> u64 {
    10
}
fn default_canary_timeout_ms() -> u64 {
    4000
}
fn default_quorum() -> String {
    "majority".to_string()
}
fn default_canary_failure_threshold() -> u32 {
    2
}
fn default_user_agent() -> String {
    concat!("vlb/", env!("CARGO_PKG_VERSION"), " (uplink-canary)").to_string()
}

/// One canary endpoint as written in TOML. Exactly one `expect_*` field may
/// be set; none means "the status code is the whole contract".
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CanaryTargetConfig {
    pub url: String,
    #[serde(default = "default_expect_status")]
    pub expect_status: u16,
    /// Body must contain this marker. Robust against line-ending changes,
    /// and a portal page will never contain it.
    pub expect_contains: Option<String>,
    /// Body must equal this string byte for byte.
    pub expect_exact: Option<String>,
    /// SHA-256 of the body, as 64 hex characters. Strictest option.
    pub expect_sha256: Option<String>,
}

fn default_expect_status() -> u16 {
    200
}

/// Built-in canary set.
///
/// Two plain-HTTP endpoints plus one HTTPS endpoint, chosen so the three
/// fail for *different* reasons and one blocked endpoint cannot cause a
/// false failover:
///
/// * the plain-HTTP pair are the industry-standard captive-portal probes
///   (the ones Android and Firefox use). Plain HTTP is what an intercepting
///   ISP rewrites, so these trip first and loudest;
/// * the HTTPS one additionally proves the TLS chain — a transparent proxy
///   cannot present a valid certificate for `raw.githubusercontent.com`,
///   so it fails the handshake instead of serving a portal page.
fn default_canary_targets() -> Vec<CanaryTargetConfig> {
    vec![
        CanaryTargetConfig {
            url: "http://connectivitycheck.gstatic.com/generate_204".into(),
            expect_status: 204,
            expect_contains: None,
            expect_exact: None,
            expect_sha256: None,
        },
        CanaryTargetConfig {
            url: "http://detectportal.firefox.com/success.txt".into(),
            expect_status: 200,
            expect_contains: None,
            expect_exact: Some("success\n".into()),
            expect_sha256: None,
        },
        CanaryTargetConfig {
            url: "https://raw.githubusercontent.com/DenisHumen/vlb-Virtual-Load-Balancer/main/canary/canary.txt".into(),
            expect_status: 200,
            expect_contains: Some(CANARY_MARKER.into()),
            expect_exact: None,
            expect_sha256: None,
        },
    ]
}

/// Marker string embedded in `canary/canary.txt` in this repository.
/// Kept as a constant so the file and the default config cannot drift.
pub const CANARY_MARKER: &str = "vlb-canary-v1-do-not-edit";

impl CanaryConfig {
    pub fn quorum_parsed(&self) -> Result<Quorum> {
        match self.quorum.trim().to_ascii_lowercase().as_str() {
            "any" => Ok(Quorum::Any),
            "majority" => Ok(Quorum::Majority),
            "all" => Ok(Quorum::All),
            other => bail!("canary.quorum must be one of any|majority|all, got {other:?}"),
        }
    }

    /// Turn the TOML shape into runtime targets, validating as we go.
    pub fn targets_parsed(&self) -> Result<Vec<CanaryTarget>> {
        let mut out = Vec::with_capacity(self.targets.len());
        for t in &self.targets {
            let url = Url::parse(&t.url)
                .with_context(|| format!("canary target {:?} has an invalid url", t.url))?;

            let set = [
                t.expect_contains.is_some(),
                t.expect_exact.is_some(),
                t.expect_sha256.is_some(),
            ];
            if set.iter().filter(|b| **b).count() > 1 {
                bail!(
                    "canary target {} sets more than one of expect_contains / \
                     expect_exact / expect_sha256 — pick exactly one",
                    t.url
                );
            }

            let expect = if let Some(s) = &t.expect_contains {
                if s.is_empty() {
                    bail!("canary target {} has an empty expect_contains", t.url);
                }
                ContentExpectation::Contains(s.clone())
            } else if let Some(s) = &t.expect_exact {
                ContentExpectation::Exact(s.clone().into_bytes())
            } else if let Some(s) = &t.expect_sha256 {
                ContentExpectation::Sha256(parse_sha256(s).with_context(|| {
                    format!("canary target {} has an invalid expect_sha256", t.url)
                })?)
            } else {
                ContentExpectation::StatusOnly
            };

            if !(100..=599).contains(&t.expect_status) {
                bail!(
                    "canary target {} has an out-of-range expect_status {}",
                    t.url,
                    t.expect_status
                );
            }
            // A canary that expects a redirect would defeat its own purpose:
            // a redirect is exactly the portal signature we look for.
            if (300..400).contains(&t.expect_status) {
                bail!(
                    "canary target {} expects a {} redirect — a redirect is the \
                     captive-portal signature this probe exists to detect, so it \
                     can never be the expected result",
                    t.url,
                    t.expect_status
                );
            }

            out.push(CanaryTarget {
                url,
                expect_status: t.expect_status,
                expect,
            });
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Failover behaviour
// ─────────────────────────────────────────────────────────────────────────

/// Switching policy: how eagerly we leave a provider and how carefully we
/// come back to it.
///
/// The two directions are intentionally asymmetric. Leaving a broken uplink
/// is urgent and unconditional — users are offline right now. Returning to a
/// recovered one is not urgent at all, and doing it too eagerly is how you
/// get a flapping gateway that resets every TCP connection each time an ISP
/// twitches. So failback waits for a sustained clean run.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FailoverConfig {
    /// How long a higher-priority provider must stay continuously healthy —
    /// every layer, including the canary — before we move back to it.
    #[serde(default = "default_failback_stable_secs")]
    pub failback_stable_secs: u64,
    /// After this many switches inside `flap_window_secs`, the failback
    /// wait is doubled (repeatedly, up to `max_failback_stable_secs`) so a
    /// genuinely unstable uplink stops yo-yoing the gateway.
    #[serde(default = "default_flap_threshold")]
    pub flap_threshold: u32,
    #[serde(default = "default_flap_window_secs")]
    pub flap_window_secs: u64,
    #[serde(default = "default_max_failback_stable_secs")]
    pub max_failback_stable_secs: u64,
    /// Periodically re-read the kernel default route and re-install ours if
    /// something else (DHCP renew, netplan apply, NetworkManager) replaced
    /// it. 0 disables the watchdog.
    #[serde(default = "default_route_watchdog_secs")]
    pub route_watchdog_secs: u64,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            failback_stable_secs: default_failback_stable_secs(),
            flap_threshold: default_flap_threshold(),
            flap_window_secs: default_flap_window_secs(),
            max_failback_stable_secs: default_max_failback_stable_secs(),
            route_watchdog_secs: default_route_watchdog_secs(),
        }
    }
}

fn default_failback_stable_secs() -> u64 {
    30
}
fn default_flap_threshold() -> u32 {
    3
}
fn default_flap_window_secs() -> u64 {
    600
}
fn default_max_failback_stable_secs() -> u64 {
    900
}
fn default_route_watchdog_secs() -> u64 {
    15
}

// ─────────────────────────────────────────────────────────────────────────
// Self-update
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// `owner/repo` on GitHub to pull releases from.
    #[serde(default = "default_update_repo")]
    pub repo: String,
    /// Allow `vlb update` to install a pre-release (`-alpha`, `-rc`) build.
    #[serde(default)]
    pub allow_prerelease: bool,
    /// Restart the systemd unit after a successful install.
    #[serde(default = "default_true")]
    pub restart_service: bool,
    #[serde(default = "default_update_service")]
    pub service_name: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            repo: default_update_repo(),
            allow_prerelease: false,
            restart_service: true,
            service_name: default_update_service(),
        }
    }
}

fn default_update_repo() -> String {
    "DenisHumen/vlb-Virtual-Load-Balancer".to_string()
}
fn default_update_service() -> String {
    "vlb".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct General {
    pub lan_interface: Option<String>,
    pub gateway_address: Option<Ipv4Addr>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Per-probe timeout in milliseconds. Fractional ping `-W` is supported
    /// by iputils, so values below 1000 ms work correctly.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    /// External probe targets. Each entry is either an IPv4 literal
    /// (e.g. `"1.1.1.1"`) or a DNS hostname (e.g. `"google.com"`).
    /// Hostnames are resolved through the provider's own mark-bound
    /// resolvers at probe time and the resulting IP is then pinged with
    /// the same fwmark — a true end-to-end test that exposes the
    /// "selectively prohibited" failure mode where an upstream router
    /// allows ICMP to popular DNS IPs but returns
    /// `Destination Net Prohibited` for general internet destinations.
    /// Mix IPs and hostnames for resilience: if hostname resolution
    /// itself flaps, the IP-based probe still works.
    #[serde(default = "default_probe_targets")]
    pub probe_targets: Vec<String>,
    /// Whether to additionally verify that DNS resolution works through
    /// each provider. Catches the "ping passes but DNS is blocked" failure
    /// mode common with unpaid ISP accounts or captive portals — the
    /// gateway and external IPs answer ICMP, but UDP/53 to public
    /// resolvers is silently dropped. Default: enabled.
    #[serde(default = "default_dns_enabled")]
    pub dns_check_enabled: bool,
    /// Public DNS resolvers to query. Each is contacted via the
    /// provider-specific fwmark (same as `probe_targets`), so the check is
    /// independent of which provider currently owns the default route.
    /// Success means at least ONE resolver returned a valid response with
    /// at least one answer record for `dns_check_name` within the timeout.
    #[serde(default = "default_dns_resolvers")]
    pub dns_resolvers: Vec<Ipv4Addr>,
    /// Hostname to resolve. Use a high-availability, low-TTL name —
    /// `cloudflare.com` (default) is a safe choice; never pick something
    /// the resolver might cache forever.
    #[serde(default = "default_dns_name")]
    pub dns_check_name: String,
    #[serde(default = "default_status_interval")]
    pub status_print_secs: u64,
    /// Ask each resolver for a random name under `.invalid`, which RFC 6761
    /// guarantees can never exist. An honest resolver says NXDOMAIN; an
    /// intercepting one invents an address. This is the cheapest possible
    /// detector for the DNS half of an unpaid-account hijack.
    #[serde(default = "default_true")]
    pub dns_integrity_check: bool,
    /// Retention for rows in `health_checks`. Without this the table grows
    /// without bound — at a 3 s interval with 4 probe kinds and 3 providers
    /// that is over 100 M rows a year. 0 disables pruning.
    #[serde(default = "default_health_retention")]
    pub retention_hours: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            timeout_ms: default_timeout_ms(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            probe_targets: default_probe_targets(),
            dns_check_enabled: default_dns_enabled(),
            dns_resolvers: default_dns_resolvers(),
            dns_check_name: default_dns_name(),
            status_print_secs: default_status_interval(),
            dns_integrity_check: true,
            retention_hours: default_health_retention(),
        }
    }
}

fn default_interval() -> u64 {
    3
}
fn default_timeout_ms() -> u64 {
    1000
}
fn default_failure_threshold() -> u32 {
    2
}
fn default_success_threshold() -> u32 {
    2
}
fn default_status_interval() -> u64 {
    30
}
fn default_health_retention() -> u32 {
    72
}
fn default_probe_targets() -> Vec<String> {
    // Two well-known DNS IPs (cheap reachability) plus a real hostname
    // (catches selectively prohibited upstreams that allow specific IPs
    // but block general traffic to e.g. google.com).
    vec![
        "1.1.1.1".to_string(),
        "8.8.8.8".to_string(),
        "google.com".to_string(),
    ]
}
fn default_dns_enabled() -> bool {
    true
}
fn default_dns_resolvers() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
}
fn default_dns_name() -> String {
    "cloudflare.com".to_string()
}

/// Per-provider policy routing configuration.
///
/// For each provider we derive a dedicated routing table and a unique
/// fwmark from its priority: `table_id = table_base + priority`,
/// `mark = fwmark_base + priority`. Probes use `ping -m <mark>` so they
/// are routed through the corresponding table — letting us verify each
/// provider's *internet* reachability independently, regardless of which
/// provider currently owns the main default route.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_table_base")]
    pub table_base: u32,
    #[serde(default = "default_fwmark_base")]
    pub fwmark_base: u32,
    #[serde(default = "default_rule_pref")]
    pub rule_pref: u32,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            table_base: default_table_base(),
            fwmark_base: default_fwmark_base(),
            rule_pref: default_rule_pref(),
        }
    }
}

fn default_table_base() -> u32 {
    200
}
fn default_fwmark_base() -> u32 {
    0x200
}
fn default_rule_pref() -> u32 {
    32000
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub manage: bool,
    #[serde(default)]
    pub disable_host_firewall: bool,
    pub wan_interface: Option<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            manage: true,
            disable_host_firewall: false,
            wan_interface: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/vlb/stats.db")
}

/// Where the balancer's control server listens. The TUI and the CLI
/// `vlb force` / `vlb status` subcommands connect here. Default is a
/// localhost-only TCP port — no auth, so do NOT expose externally.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    #[serde(default = "default_control_listen")]
    pub listen: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            listen: default_control_listen(),
        }
    }
}

fn default_control_listen() -> String {
    "127.0.0.1:7650".to_string()
}

/// Traffic counter sampling. We read `/proc/net/dev` for each provider
/// interface and derive per-tick rx/tx deltas, both in bytes and packets.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrafficConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_traffic_interval")]
    pub interval_secs: u64,
    /// How long raw samples are kept before being pruned. 0 disables pruning.
    #[serde(default = "default_traffic_retention")]
    pub retention_hours: u32,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_traffic_interval(),
            retention_hours: default_traffic_retention(),
        }
    }
}

fn default_traffic_interval() -> u64 {
    2
}
fn default_traffic_retention() -> u32 {
    72
}

/// Host-wide system metrics sampling (btop-style: CPU/RAM/swap/load/disks).
/// The same DB that stores traffic also stores system samples, so the TUI
/// can render everything from a single live query.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_system_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_system_retention")]
    pub retention_hours: u32,
    /// Store per-core CPU % as a JSON array in the DB. Costs ~16 bytes per
    /// core per sample; disable on large-SMT boxes if DB size matters.
    #[serde(default = "default_true")]
    pub per_core: bool,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_system_interval(),
            retention_hours: default_system_retention(),
            per_core: true,
        }
    }
}

fn default_system_interval() -> u64 {
    2
}
fn default_system_retention() -> u32 {
    72
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub name: String,
    pub gateway: Ipv4Addr,
    pub interface: String,
    pub priority: u32,
    #[serde(default)]
    pub role: ProviderRole,
}

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderRole {
    #[default]
    Primary,
    Backup,
}

impl ProviderRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderRole::Primary => "primary",
            ProviderRole::Backup => "backup",
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw).context("failed to parse TOML config")?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.providers.is_empty() {
            bail!("at least one provider must be configured");
        }
        // Priorities only need to be unique. Gaps are explicitly fine — a
        // 0 / 2 pair is a perfectly good "primary, then this one", and
        // leaving room in between lets you slot a provider in later without
        // renumbering (which would move its routing table and fwmark).
        // Nothing requires a provider at priority 0; the lowest number
        // present simply wins.
        let mut priorities: Vec<u32> = self.providers.iter().map(|p| p.priority).collect();
        priorities.sort_unstable();
        let original_len = priorities.len();
        priorities.dedup();
        if priorities.len() != original_len {
            bail!("providers must have unique priority values");
        }
        let mut names: Vec<&str> = self.providers.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        let orig = names.len();
        names.dedup();
        if names.len() != orig {
            bail!("providers must have unique names");
        }
        for p in &self.providers {
            if p.name.trim().is_empty() {
                bail!("provider name must not be empty");
            }
            if p.name.chars().any(|c| c.is_whitespace()) {
                bail!("provider name '{}' must not contain whitespace", p.name);
            }
            if p.interface.trim().is_empty() {
                bail!("provider '{}' has empty interface name", p.name);
            }
            // Linux kernel IFNAMSIZ is 16 including NUL — enforce 15 to be safe.
            if p.interface.len() > 15 {
                bail!(
                    "provider '{}' interface name '{}' exceeds Linux IFNAMSIZ-1 (15 chars)",
                    p.name,
                    p.interface
                );
            }
            if p.interface
                .chars()
                .any(|c| c.is_whitespace() || c == '/' || c == ':')
            {
                bail!(
                    "provider '{}' interface name '{}' contains forbidden characters",
                    p.name,
                    p.interface
                );
            }
            if p.gateway.is_unspecified() {
                bail!("provider '{}' gateway must not be 0.0.0.0", p.name);
            }
            if p.gateway.is_broadcast() {
                bail!(
                    "provider '{}' gateway must not be the broadcast address",
                    p.name
                );
            }
            if p.gateway.is_multicast() {
                bail!(
                    "provider '{}' gateway must not be a multicast address",
                    p.name
                );
            }
        }
        if self.health.interval_secs == 0 {
            bail!("health.interval_secs must be >= 1");
        }
        if self.health.timeout_ms < 100 {
            bail!("health.timeout_ms must be >= 100");
        }
        // Timeout must be strictly less than the interval, otherwise probe
        // dispatch slips behind the ticker and thresholds become meaningless.
        if self.health.timeout_ms >= self.health.interval_secs.saturating_mul(1000) {
            bail!(
                "health.timeout_ms ({}) must be < health.interval_secs*1000 ({}ms)",
                self.health.timeout_ms,
                self.health.interval_secs * 1000
            );
        }
        if self.health.failure_threshold == 0 || self.health.success_threshold == 0 {
            bail!("health thresholds must be >= 1");
        }
        if self.health.probe_targets.is_empty() {
            bail!(
                "health.probe_targets must not be empty — at least one external target is required for end-to-end probing"
            );
        }
        for t in &self.health.probe_targets {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                bail!("health.probe_targets contains an empty entry");
            }
            if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                if ip.is_unspecified() || ip.is_loopback() || ip.is_broadcast() || ip.is_multicast()
                {
                    bail!("health.probe_targets contains invalid address {ip}");
                }
            } else {
                // Treat as hostname — enforce a sane DNS-name shape so a
                // typo doesn't get silently sent to the resolver every
                // probe interval.
                if trimmed.len() > 253 || !trimmed.contains('.') {
                    bail!("health.probe_targets entry {trimmed:?} is not a valid IPv4 or FQDN");
                }
                if !trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                {
                    bail!("health.probe_targets entry {trimmed:?} contains invalid characters");
                }
            }
        }
        if self.health.dns_check_enabled
            || self
                .health
                .probe_targets
                .iter()
                .any(|t| t.parse::<Ipv4Addr>().is_err())
        {
            // DNS resolvers are required either for the explicit DNS
            // probe OR to resolve any hostname-based internet target.
            if self.health.dns_resolvers.is_empty() {
                bail!(
                    "health.dns_resolvers must not be empty when DNS-based probing is in use (dns_check_enabled or hostname probe_targets)"
                );
            }
            for r in &self.health.dns_resolvers {
                if r.is_unspecified() || r.is_loopback() || r.is_broadcast() || r.is_multicast() {
                    bail!("health.dns_resolvers contains invalid address {r}");
                }
            }
        }
        if self.health.dns_check_enabled {
            let n = self.health.dns_check_name.trim();
            if n.is_empty() || n.len() > 253 || !n.contains('.') {
                bail!("health.dns_check_name must be a non-empty FQDN (e.g. cloudflare.com)");
            }
        }
        if self.health.status_print_secs < 5 {
            bail!("health.status_print_secs must be >= 5");
        }

        // Routing-table reservations: 0 unspec, 253 default, 254 main,
        // 255 local. `table_for(p) = table_base + priority`.
        let max_prio = self.providers.iter().map(|p| p.priority).max().unwrap_or(0);
        let first_table = self.routing.table_base;
        let last_table = self.routing.table_base.saturating_add(max_prio);
        if first_table == 0 {
            bail!("routing.table_base must not be 0 (reserved — unspec)");
        }
        for reserved in [253u32, 254, 255] {
            if (first_table..=last_table).contains(&reserved) {
                bail!(
                    "routing.table_base..={last_table} overlaps reserved table {reserved} \
                     (253=default, 254=main, 255=local) — pick a different table_base"
                );
            }
        }
        if last_table > 0xFFFF_FFFE {
            bail!("routing.table_base + max priority overflows u32");
        }
        // ip rule prefs are bounded by 0..=32766 for main and we want our
        // rules strictly above user overrides but below the main default.
        let max_pref = self.routing.rule_pref.saturating_add(max_prio);
        if max_pref >= 32766 {
            bail!(
                "routing.rule_pref + max priority ({max_pref}) must be < 32766 (the main-table pref)"
            );
        }
        // fwmark is an arbitrary 32-bit value; only ensure it's non-zero so
        // it doesn't collide with "no mark" and stays in a safe range.
        if self.routing.fwmark_base == 0 {
            bail!("routing.fwmark_base must not be 0");
        }
        if self.routing.fwmark_base.checked_add(max_prio).is_none() {
            bail!("routing.fwmark_base + max priority overflows u32");
        }

        // Control server: empty listen is a config error; parse validated by
        // the listener itself, but we eagerly check so `vlb check` catches
        // typos before service start.
        if self.control.listen.trim().is_empty() {
            bail!("control.listen must not be empty");
        }
        let parsed_listen: std::net::SocketAddr = self.control.listen.parse().map_err(|_| {
            anyhow::anyhow!(
                "control.listen '{}' is not a valid IP:port (example: 127.0.0.1:7650)",
                self.control.listen
            )
        })?;
        // The control protocol is unauthenticated. Binding it to anything
        // other than a loopback address would let any host on the network
        // force a provider over to themselves or read traffic stats. We
        // hard-fail here so a misconfiguration never makes it to runtime.
        if !parsed_listen.ip().is_loopback() {
            bail!(
                "control.listen '{}' is not a loopback address — the control \
                 protocol has no authentication and must only bind to 127.0.0.1 \
                 or ::1. Put a reverse-proxy with auth in front if remote \
                 access is required.",
                self.control.listen
            );
        }
        if self.traffic.enabled && self.traffic.interval_secs == 0 {
            bail!("traffic.interval_secs must be >= 1 when traffic.enabled = true");
        }
        if self.system.enabled && self.system.interval_secs == 0 {
            bail!("system.interval_secs must be >= 1 when system.enabled = true");
        }

        // ── canary ──────────────────────────────────────────────────────
        if self.canary.enabled {
            if self.canary.targets.is_empty() {
                bail!(
                    "canary.enabled = true but canary.targets is empty — either add \
                     targets or set canary.enabled = false. Note that disabling the \
                     canary removes the only check that can detect an uplink which \
                     is reachable but intercepted (unpaid account / captive portal)."
                );
            }
            if self.canary.interval_secs == 0 {
                bail!("canary.interval_secs must be >= 1");
            }
            if self.canary.timeout_ms < 200 {
                bail!("canary.timeout_ms must be >= 200");
            }
            // Each round must fit inside its own interval, or rounds pile up
            // and the effective detection time silently doubles.
            if self.canary.timeout_ms >= self.canary.interval_secs.saturating_mul(1000) {
                bail!(
                    "canary.timeout_ms ({}) must be < canary.interval_secs*1000 ({}ms), \
                     otherwise a slow round overruns the next one",
                    self.canary.timeout_ms,
                    self.canary.interval_secs * 1000
                );
            }
            if self.canary.failure_threshold == 0 {
                bail!("canary.failure_threshold must be >= 1");
            }
            // Parse eagerly so `vlb check` reports a bad url or digest now,
            // rather than the daemon discovering it at the first probe.
            let quorum = self.canary.quorum_parsed()?;
            let targets = self.canary.targets_parsed()?;
            let required = quorum.required(targets.len());
            if required > targets.len() {
                bail!(
                    "canary.quorum = {:?} needs {required} passing targets but only {} \
                     are configured",
                    self.canary.quorum,
                    targets.len()
                );
            }
            // A single target under `majority`/`all` means any hiccup at that
            // one endpoint fails the provider over. Allowed, but say so.
            if targets.len() == 1 && !matches!(quorum, Quorum::Any) {
                tracing::warn!(
                    "canary has a single target with quorum = {:?}: an outage at that \
                     one endpoint will fail providers over. Two or more targets are \
                     strongly recommended.",
                    self.canary.quorum
                );
            }
            if self.canary.user_agent.trim().is_empty() {
                bail!("canary.user_agent must not be empty");
            }
        }

        // ── failover ────────────────────────────────────────────────────
        if self.failover.flap_threshold == 0 {
            bail!("failover.flap_threshold must be >= 1");
        }
        if self.failover.max_failback_stable_secs < self.failover.failback_stable_secs {
            bail!(
                "failover.max_failback_stable_secs ({}) must be >= \
                 failover.failback_stable_secs ({})",
                self.failover.max_failback_stable_secs,
                self.failover.failback_stable_secs
            );
        }

        // ── update ──────────────────────────────────────────────────────
        let repo = self.update.repo.trim();
        if repo.is_empty() || repo.matches('/').count() != 1 {
            bail!("update.repo must be in `owner/name` form, got {repo:?}");
        }
        if !repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
        {
            bail!("update.repo {repo:?} contains characters that are not valid in a GitHub path");
        }
        if self.update.service_name.trim().is_empty() {
            bail!("update.service_name must not be empty");
        }

        Ok(())
    }

    /// Human-readable summary of the loaded configuration — used by the
    /// `vlb check` subcommand for a quick eyeball before deploying.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "general:");
        let _ = writeln!(
            s,
            "  lan_interface   = {}",
            self.general.lan_interface.as_deref().unwrap_or("(unset)")
        );
        let _ = writeln!(
            s,
            "  gateway_address = {}",
            self.general
                .gateway_address
                .map(|a| a.to_string())
                .unwrap_or_else(|| "(unset)".into())
        );
        let _ = writeln!(s, "health:");
        let _ = writeln!(
            s,
            "  interval={}s timeout={}ms fail={} ok={} status_every={}s",
            self.health.interval_secs,
            self.health.timeout_ms,
            self.health.failure_threshold,
            self.health.success_threshold,
            self.health.status_print_secs
        );
        let _ = writeln!(s, "  probe_targets={:?}", self.health.probe_targets);
        let _ = writeln!(
            s,
            "  dns_check={} resolvers={:?} name={}",
            self.health.dns_check_enabled, self.health.dns_resolvers, self.health.dns_check_name
        );
        let _ = writeln!(
            s,
            "  dns_integrity_check={} retention={}h",
            self.health.dns_integrity_check, self.health.retention_hours
        );
        let _ = writeln!(s, "canary (content authenticity):");
        if !self.canary.enabled {
            let _ = writeln!(
                s,
                "  DISABLED — an intercepted-but-reachable uplink will NOT be detected"
            );
        } else {
            let _ = writeln!(
                s,
                "  interval={}s timeout={}ms quorum={} fail_after={}",
                self.canary.interval_secs,
                self.canary.timeout_ms,
                self.canary.quorum,
                self.canary.failure_threshold
            );
            match self.canary.targets_parsed() {
                Ok(targets) => {
                    for t in &targets {
                        let _ = writeln!(
                            s,
                            "  - {} (expect HTTP {}, {})",
                            t.url,
                            t.expect_status,
                            t.expect.describe()
                        );
                    }
                }
                Err(e) => {
                    let _ = writeln!(s, "  <invalid: {e}>");
                }
            }
        }
        let _ = writeln!(s, "failover:");
        let _ = writeln!(
            s,
            "  failback_stable={}s flap_threshold={} flap_window={}s max_failback={}s watchdog={}s",
            self.failover.failback_stable_secs,
            self.failover.flap_threshold,
            self.failover.flap_window_secs,
            self.failover.max_failback_stable_secs,
            self.failover.route_watchdog_secs
        );
        let _ = writeln!(s, "update:");
        let _ = writeln!(
            s,
            "  repo={} allow_prerelease={} restart_service={} unit={}",
            self.update.repo,
            self.update.allow_prerelease,
            self.update.restart_service,
            self.update.service_name
        );
        let _ = writeln!(s, "routing:");
        let _ = writeln!(
            s,
            "  table_base={} fwmark_base=0x{:x} rule_pref={}",
            self.routing.table_base, self.routing.fwmark_base, self.routing.rule_pref
        );
        let _ = writeln!(s, "firewall:");
        let _ = writeln!(
            s,
            "  manage={} disable_host_firewall={} wan_interface={:?}",
            self.firewall.manage, self.firewall.disable_host_firewall, self.firewall.wan_interface
        );
        let _ = writeln!(s, "database:");
        let _ = writeln!(s, "  path={}", self.database.path.display());
        let _ = writeln!(s, "control:");
        let _ = writeln!(s, "  listen={}", self.control.listen);
        let _ = writeln!(
            s,
            "traffic:\n  enabled={} interval={}s retention={}h",
            self.traffic.enabled, self.traffic.interval_secs, self.traffic.retention_hours
        );
        let _ = writeln!(
            s,
            "system:\n  enabled={} interval={}s retention={}h per_core={}",
            self.system.enabled,
            self.system.interval_secs,
            self.system.retention_hours,
            self.system.per_core
        );
        let _ = writeln!(s, "providers ({}):", self.providers.len());
        let mut sorted: Vec<&Provider> = self.providers.iter().collect();
        sorted.sort_by_key(|p| p.priority);
        for p in sorted {
            let _ = writeln!(
                s,
                "  [{}] {} -> {} via {} (role={}, table={}, mark=0x{:x}, pref={})",
                p.priority,
                p.name,
                p.gateway,
                p.interface,
                p.role.as_str(),
                self.table_for(p),
                self.mark_for(p),
                self.rule_pref_for(p),
            );
        }
        s
    }

    /// Routing table ID for the provider — derived from its priority so the
    /// mapping is stable across restarts and easy to read with `ip route
    /// show table N`.
    pub fn table_for(&self, p: &Provider) -> u32 {
        self.routing.table_base + p.priority
    }

    /// Firewall mark used by probes to select this provider's routing
    /// table via `ip rule fwmark M lookup T`.
    pub fn mark_for(&self, p: &Provider) -> u32 {
        self.routing.fwmark_base + p.priority
    }

    /// `ip rule` pref value — unique per provider, in a range well above
    /// the main table (32766) so we don't collide with kernel defaults.
    pub fn rule_pref_for(&self, p: &Provider) -> u32 {
        self.routing.rule_pref + p.priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str, prio: u32) -> Provider {
        Provider {
            name: name.into(),
            gateway: format!("10.0.0.{}", prio + 1).parse().unwrap(),
            interface: "eth0".into(),
            priority: prio,
            role: ProviderRole::Primary,
        }
    }

    fn base_cfg(providers: Vec<Provider>) -> Config {
        Config {
            general: General::default(),
            health: HealthConfig::default(),
            // Tests run offline: the canary would try real network I/O, so
            // it is off by default here and enabled explicitly where a test
            // is specifically about canary validation.
            canary: CanaryConfig {
                enabled: false,
                ..CanaryConfig::default()
            },
            failover: FailoverConfig::default(),
            update: UpdateConfig::default(),
            firewall: FirewallConfig::default(),
            routing: RoutingConfig::default(),
            database: DatabaseConfig::default(),
            control: ControlConfig::default(),
            traffic: TrafficConfig::default(),
            system: SystemConfig::default(),
            providers,
        }
    }

    #[test]
    fn validate_ok_minimal() {
        let cfg = base_cfg(vec![provider("p0", 0)]);
        cfg.validate().unwrap();
    }

    /// Priorities no longer have to start at 0, and gaps are fine. A
    /// "0 and 2" pair — the shape an operator reaches for when leaving room
    /// to slot in a third uplink later — must validate, and the lower number
    /// must win.
    #[test]
    fn validate_allows_priority_gaps_and_nonzero_start() {
        base_cfg(vec![provider("main", 0), provider("backup", 2)])
            .validate()
            .expect("0 and 2 with a gap must be valid");

        base_cfg(vec![provider("a", 1), provider("b", 2)])
            .validate()
            .expect("priorities need not include 0");

        base_cfg(vec![provider("solo", 7)])
            .validate()
            .expect("a single provider at any priority must be valid");
    }

    /// Routing tables, fwmarks and rule prefs are all derived from the
    /// priority, so a gap must produce a gap in each of them rather than
    /// collapsing two providers onto the same table.
    #[test]
    fn priority_gap_keeps_tables_and_marks_distinct() {
        let providers = vec![provider("main", 0), provider("backup", 2)];
        let cfg = base_cfg(providers.clone());
        assert_eq!(cfg.table_for(&providers[0]), 200);
        assert_eq!(cfg.table_for(&providers[1]), 202);
        assert_ne!(cfg.mark_for(&providers[0]), cfg.mark_for(&providers[1]));
        assert_ne!(
            cfg.rule_pref_for(&providers[0]),
            cfg.rule_pref_for(&providers[1])
        );
    }

    #[test]
    fn validate_rejects_duplicate_priority() {
        let cfg = base_cfg(vec![provider("a", 0), provider("b", 0)]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_names() {
        let mut p1 = provider("same", 0);
        let mut p2 = provider("same", 1);
        p1.name = "dup".into();
        p2.name = "dup".into();
        let cfg = base_cfg(vec![p1, p2]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_whitespace_in_name() {
        let mut p = provider("bad name", 0);
        p.name = "bad name".into();
        let cfg = base_cfg(vec![p]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_long_interface() {
        let mut p = provider("p", 0);
        p.interface = "a".repeat(20);
        let cfg = base_cfg(vec![p]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_timeout_ge_interval() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.health.interval_secs = 1;
        cfg.health.timeout_ms = 1500;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_reserved_table() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.routing.table_base = 254; // main
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_rule_pref_too_high() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.routing.rule_pref = 32766;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_probe_targets() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.health.probe_targets = vec!["127.0.0.1".to_string()];
        assert!(cfg.validate().is_err());
        cfg.health.probe_targets = vec!["not a hostname!".to_string()];
        assert!(cfg.validate().is_err());
        cfg.health.probe_targets = vec!["nodot".to_string()];
        assert!(cfg.validate().is_err());
        cfg.health.probe_targets = vec!["google.com".to_string(), "1.1.1.1".to_string()];
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_non_loopback_control_listen() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.control.listen = "0.0.0.0:7650".into();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("loopback"),
            "expected loopback-only error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_ipv6_loopback_listen() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.control.listen = "[::1]:7650".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn mark_table_pref_derivations() {
        let providers = vec![provider("a", 0), provider("b", 2)];
        let cfg = base_cfg(providers.clone());
        assert_eq!(cfg.table_for(&providers[0]), 200);
        assert_eq!(cfg.table_for(&providers[1]), 202);
        assert_eq!(cfg.mark_for(&providers[0]), 0x200);
        assert_eq!(cfg.mark_for(&providers[1]), 0x202);
        assert_eq!(cfg.rule_pref_for(&providers[0]), 32000);
        assert_eq!(cfg.rule_pref_for(&providers[1]), 32002);
    }

    #[test]
    fn summary_contains_providers() {
        let cfg = base_cfg(vec![provider("alpha", 0), provider("beta", 1)]);
        cfg.validate().unwrap();
        let s = cfg.summary();
        assert!(s.contains("alpha"));
        assert!(s.contains("beta"));
        assert!(s.contains("table=200"));
    }

    #[test]
    fn validate_rejects_zero_fwmark() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.routing.fwmark_base = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_main_and_local_tables() {
        for t in [253u32, 254, 255] {
            let mut cfg = base_cfg(vec![provider("p", 0)]);
            cfg.routing.table_base = t;
            assert!(
                cfg.validate().is_err(),
                "table {t} should have been rejected"
            );
        }
    }

    #[test]
    fn validate_rejects_dns_resolver_loopback() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.health.dns_check_enabled = true;
        cfg.health.dns_resolvers = vec!["127.0.0.1".parse().unwrap()];
        assert!(cfg.validate().is_err());
    }

    fn canary_cfg(targets: Vec<CanaryTargetConfig>, quorum: &str) -> Config {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.canary = CanaryConfig {
            enabled: true,
            quorum: quorum.into(),
            targets,
            ..CanaryConfig::default()
        };
        cfg
    }

    fn ct(url: &str) -> CanaryTargetConfig {
        CanaryTargetConfig {
            url: url.into(),
            expect_status: 200,
            expect_contains: None,
            expect_exact: None,
            expect_sha256: None,
        }
    }

    /// The default canary config fetches `canary/canary.txt` from this
    /// repository and looks for [`CANARY_MARKER`] in it. If the file and the
    /// constant ever drift apart, every deployment running the defaults would
    /// conclude its primary uplink had been hijacked and fail over — so the
    /// two are pinned together here, at compile time.
    #[test]
    fn shipped_canary_file_contains_the_marker() {
        let file = include_str!("../../canary/canary.txt");
        assert!(
            file.contains(CANARY_MARKER),
            "canary/canary.txt no longer contains {CANARY_MARKER:?} — the default \
             canary target would fail for every deployment"
        );
        // The marker must be on the first line: the file documents that
        // nothing may be inserted above it.
        assert_eq!(
            file.lines().next().map(str::trim),
            Some(CANARY_MARKER),
            "the marker must remain the first line of canary/canary.txt"
        );
        // Guard the default target's URL against a typo'd path.
        let url = &default_canary_targets()[2].url;
        assert!(
            url.ends_with("/canary/canary.txt"),
            "default canary URL {url} does not point at the shipped file"
        );
    }

    #[test]
    fn canary_defaults_validate_and_parse() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.canary = CanaryConfig::default();
        cfg.validate()
            .expect("shipped canary defaults must be valid");

        let targets = cfg.canary.targets_parsed().unwrap();
        assert_eq!(targets.len(), 3);
        // Mixed schemes on purpose: plain HTTP catches the portal rewrite,
        // HTTPS catches a MITM that proxies HTTP correctly.
        assert!(
            targets
                .iter()
                .any(|t| t.url.scheme == crate::http::Scheme::Http)
        );
        assert!(
            targets
                .iter()
                .any(|t| t.url.scheme == crate::http::Scheme::Https)
        );
        // Majority of 3 is 2, so one endpoint being unreachable is tolerated.
        assert_eq!(cfg.canary.quorum_parsed().unwrap().required(3), 2);
    }

    #[test]
    fn canary_rejects_conflicting_expectations() {
        let mut t = ct("http://example.com/x");
        t.expect_contains = Some("a".into());
        t.expect_sha256 = Some("0".repeat(64));
        let err = canary_cfg(vec![t], "any")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn canary_rejects_expecting_a_redirect() {
        // Expecting a 3xx would make the probe blind to the exact thing it
        // exists to catch.
        let mut t = ct("http://example.com/x");
        t.expect_status = 302;
        let err = canary_cfg(vec![t], "any")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("captive-portal signature"), "{err}");
    }

    #[test]
    fn canary_rejects_bad_urls_and_digests() {
        let err = canary_cfg(vec![ct("ftp://example.com/x")], "any")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid url"), "{err}");

        let mut t = ct("http://example.com/x");
        t.expect_sha256 = Some("not-a-digest".into());
        assert!(canary_cfg(vec![t], "any").validate().is_err());
    }

    #[test]
    fn canary_rejects_empty_targets_when_enabled() {
        let err = canary_cfg(vec![], "majority")
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("canary.targets is empty"), "{err}");
    }

    #[test]
    fn canary_rejects_timeout_overrunning_interval() {
        let mut cfg = canary_cfg(vec![ct("http://example.com/x")], "any");
        cfg.canary.interval_secs = 2;
        cfg.canary.timeout_ms = 5000;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("overruns"), "{err}");
    }

    #[test]
    fn canary_rejects_unknown_quorum() {
        assert!(
            canary_cfg(vec![ct("http://example.com/x")], "sometimes")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn failover_rejects_max_below_base() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        cfg.failover.failback_stable_secs = 100;
        cfg.failover.max_failback_stable_secs = 50;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn update_repo_shape_is_enforced() {
        let mut cfg = base_cfg(vec![provider("p", 0)]);
        for bad in ["", "no-slash", "a/b/c", "owner/na me"] {
            cfg.update.repo = bad.into();
            assert!(cfg.validate().is_err(), "{bad:?} should be rejected");
        }
        cfg.update.repo = "DenisHumen/vlb-Virtual-Load-Balancer".into();
        cfg.validate().unwrap();
    }

    /// A typo in a key name used to be silently ignored, leaving the default
    /// in place — e.g. `probe_target` (singular) would look accepted while
    /// the daemon quietly probed the built-in list instead.
    #[test]
    fn unknown_keys_are_rejected_not_silently_ignored() {
        let raw = r#"
[health]
probe_target = ["1.1.1.1"]

[[providers]]
name = "p"
gateway = "10.0.0.2"
interface = "eth0"
priority = 0
"#;
        let err = toml::from_str::<Config>(raw).unwrap_err().to_string();
        assert!(err.contains("probe_target"), "{err}");
    }

    #[test]
    fn toml_parse_with_canary_and_failover_sections() {
        let raw = r#"
[health]
probe_targets = ["1.1.1.1", "google.com"]

[canary]
enabled = true
interval_secs = 10
timeout_ms = 4000
quorum = "majority"

[[canary.targets]]
url = "http://connectivitycheck.gstatic.com/generate_204"
expect_status = 204

[[canary.targets]]
url = "https://raw.githubusercontent.com/o/r/main/canary/canary.txt"
expect_contains = "vlb-canary-v1-do-not-edit"

[failover]
failback_stable_secs = 45

[[providers]]
name = "main"
gateway = "10.0.0.2"
interface = "eth0"
priority = 0

[[providers]]
name = "backup"
gateway = "10.0.0.1"
interface = "eth0"
priority = 2
"#;
        let parsed: Config = toml::from_str(raw).expect("parse");
        parsed.validate().expect("validate");
        assert_eq!(parsed.canary.targets.len(), 2);
        assert_eq!(parsed.failover.failback_stable_secs, 45);
        let targets = parsed.canary.targets_parsed().unwrap();
        assert_eq!(targets[0].expect_status, 204);
        assert_eq!(targets[0].expect, ContentExpectation::StatusOnly);
        assert!(matches!(targets[1].expect, ContentExpectation::Contains(_)));
    }

    #[test]
    fn toml_parse_minimal() {
        let raw = r#"
[general]
lan_interface = "eth0"
gateway_address = "10.0.0.1"

[health]
probe_targets = ["1.1.1.1", "google.com"]

[[providers]]
name = "p"
gateway = "10.0.0.2"
interface = "eth0"
priority = 0
role = "primary"
"#;
        let parsed: Config = toml::from_str(raw).expect("parse");
        parsed.validate().unwrap();
        assert_eq!(parsed.providers.len(), 1);
        assert_eq!(parsed.providers[0].name, "p");
    }
}
