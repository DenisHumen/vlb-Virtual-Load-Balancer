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
        if self.health.interval_secs == 0 {
            bail!("health.interval_secs must be >= 1");
        }
        if self.health.timeout_ms < 100 {
            bail!("health.timeout_ms must be >= 100");
        }
        if self.health.failure_threshold == 0 || self.health.success_threshold == 0 {
            bail!("health thresholds must be >= 1");
        }
        if self.health.probe_targets.is_empty() {
            bail!("health.probe_targets must not be empty — at least one external target is required for end-to-end probing");
        }
        Ok(())
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
