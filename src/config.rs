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
    #[serde(default = "default_probe_targets")]
    pub probe_targets: Vec<Ipv4Addr>,
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
            status_print_secs: default_status_interval(),
        }
    }
}

fn default_interval() -> u64 { 3 }
fn default_timeout_ms() -> u64 { 1000 }
fn default_failure_threshold() -> u32 { 2 }
fn default_success_threshold() -> u32 { 2 }
fn default_status_interval() -> u64 { 30 }
fn default_probe_targets() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
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
            if t.is_unspecified() || t.is_loopback() || t.is_broadcast() || t.is_multicast() {
                bail!("health.probe_targets contains invalid address {t}");
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
        cfg.health.probe_targets = vec!["127.0.0.1".parse().unwrap()];
        assert!(cfg.validate().is_err());
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
