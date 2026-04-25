use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub health: HealthConfig,
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
    pub providers: Vec<Provider>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct General {
    pub lan_interface: Option<String>,
    pub gateway_address: Option<Ipv4Addr>,
}

#[derive(Debug, Deserialize, Clone)]
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
        }
    }
}

fn default_interval() -> u64 { 3 }
fn default_timeout_ms() -> u64 { 1000 }
fn default_failure_threshold() -> u32 { 2 }
fn default_success_threshold() -> u32 { 2 }
fn default_status_interval() -> u64 { 30 }
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
fn default_dns_enabled() -> bool { true }
fn default_dns_resolvers() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
}
fn default_dns_name() -> String { "cloudflare.com".to_string() }

/// Per-provider policy routing configuration.
///
/// For each provider we derive a dedicated routing table and a unique
/// fwmark from its priority: `table_id = table_base + priority`,
/// `mark = fwmark_base + priority`. Probes use `ping -m <mark>` so they
/// are routed through the corresponding table — letting us verify each
/// provider's *internet* reachability independently, regardless of which
/// provider currently owns the main default route.
#[derive(Debug, Deserialize, Clone)]
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

fn default_table_base() -> u32 { 200 }
fn default_fwmark_base() -> u32 { 0x200 }
fn default_rule_pref() -> u32 { 32000 }

#[derive(Debug, Deserialize, Clone)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub manage: bool,
    #[serde(default)]
    pub disable_host_firewall: bool,
    pub wan_interface: Option<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self { manage: true, disable_host_firewall: false, wan_interface: None }
    }
}

fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self { Self { path: default_db_path() } }
}

fn default_db_path() -> PathBuf { PathBuf::from("/var/lib/vlb/stats.db") }

/// Where the balancer's control server listens. The TUI and the CLI
/// `vlb force` / `vlb status` subcommands connect here. Default is a
/// localhost-only TCP port — no auth, so do NOT expose externally.
#[derive(Debug, Deserialize, Clone)]
pub struct ControlConfig {
    #[serde(default = "default_control_listen")]
    pub listen: String,
}

impl Default for ControlConfig {
    fn default() -> Self { Self { listen: default_control_listen() } }
}

fn default_control_listen() -> String { "127.0.0.1:7650".to_string() }

/// Traffic counter sampling. We read `/proc/net/dev` for each provider
/// interface and derive per-tick rx/tx deltas, both in bytes and packets.
#[derive(Debug, Deserialize, Clone)]
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

fn default_traffic_interval() -> u64 { 2 }
fn default_traffic_retention() -> u32 { 72 }

/// Host-wide system metrics sampling (btop-style: CPU/RAM/swap/load/disks).
/// The same DB that stores traffic also stores system samples, so the TUI
/// can render everything from a single live query.
#[derive(Debug, Deserialize, Clone)]
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

fn default_system_interval() -> u64 { 2 }
fn default_system_retention() -> u32 { 72 }

#[derive(Debug, Deserialize, Clone)]
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
        if !self.providers.iter().any(|p| p.priority == 0) {
            bail!("at least one provider must have priority = 0 (primary)");
        }
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
            if p.interface.chars().any(|c| c.is_whitespace() || c == '/' || c == ':') {
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
                bail!("provider '{}' gateway must not be the broadcast address", p.name);
            }
            if p.gateway.is_multicast() {
                bail!("provider '{}' gateway must not be a multicast address", p.name);
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
            bail!("health.probe_targets must not be empty — at least one external target is required for end-to-end probing");
        }
        for t in &self.health.probe_targets {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                bail!("health.probe_targets contains an empty entry");
            }
            if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                if ip.is_unspecified() || ip.is_loopback() || ip.is_broadcast() || ip.is_multicast() {
                    bail!("health.probe_targets contains invalid address {ip}");
                }
            } else {
                // Treat as hostname — enforce a sane DNS-name shape so a
                // typo doesn't get silently sent to the resolver every
                // probe interval.
                if trimmed.len() > 253 || !trimmed.contains('.') {
                    bail!(
                        "health.probe_targets entry {:?} is not a valid IPv4 or FQDN",
                        trimmed
                    );
                }
                if !trimmed.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
                }) {
                    bail!(
                        "health.probe_targets entry {:?} contains invalid characters",
                        trimmed
                    );
                }
            }
        }
        if self.health.dns_check_enabled || self.health.probe_targets.iter().any(|t| t.parse::<Ipv4Addr>().is_err()) {
            // DNS resolvers are required either for the explicit DNS
            // probe OR to resolve any hostname-based internet target.
            if self.health.dns_resolvers.is_empty() {
                bail!("health.dns_resolvers must not be empty when DNS-based probing is in use (dns_check_enabled or hostname probe_targets)");
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
        if self
            .routing
            .fwmark_base
            .checked_add(max_prio)
            .is_none()
        {
            bail!("routing.fwmark_base + max priority overflows u32");
        }

        // Control server: empty listen is a config error; parse validated by
        // the listener itself, but we eagerly check so `vlb check` catches
        // typos before service start.
        if self.control.listen.trim().is_empty() {
            bail!("control.listen must not be empty");
        }
        let parsed_listen: std::net::SocketAddr = self
            .control
            .listen
            .parse()
            .map_err(|_| anyhow::anyhow!(
                "control.listen '{}' is not a valid IP:port (example: 127.0.0.1:7650)",
                self.control.listen
            ))?;
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
        let _ = writeln!(s, "  interval={}s timeout={}ms fail={} ok={} status_every={}s",
            self.health.interval_secs,
            self.health.timeout_ms,
            self.health.failure_threshold,
            self.health.success_threshold,
            self.health.status_print_secs);
        let _ = writeln!(s, "  probe_targets={:?}", self.health.probe_targets);
        let _ = writeln!(
            s,
            "  dns_check={} resolvers={:?} name={}",
            self.health.dns_check_enabled,
            self.health.dns_resolvers,
            self.health.dns_check_name
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

    #[test]
    fn validate_requires_priority_zero() {
        let cfg = base_cfg(vec![provider("p1", 1)]);
        assert!(cfg.validate().is_err());
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
}
