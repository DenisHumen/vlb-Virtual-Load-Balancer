use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

use crate::config::Provider;
use crate::sysmon::SysSample;
use crate::traffic::IfCounters;

pub struct Stats {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct HealthRecord {
    pub provider: String,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub latency_ms: Option<f64>,
    pub kind: &'static str, // "gateway" | "internet"
}

#[derive(Debug, Clone)]
pub struct FailoverRecord {
    pub timestamp: DateTime<Utc>,
    pub from_provider: Option<String>,
    pub to_provider: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct TrafficPoint {
    pub ts: DateTime<Utc>,
    pub interval_s: f64,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

/// Aggregate over a time window. Totals are i64 because SQLite's SUM is
/// signed; values are non-negative in practice.
#[derive(Debug, Clone)]
pub struct TrafficTotals {
    pub provider: String,
    pub rx_bytes: i64,
    pub rx_packets: i64,
    pub tx_bytes: i64,
    pub tx_packets: i64,
}

/// One row of `system_samples`, wire-compatible with the control protocol.
#[derive(Debug, Clone)]
pub struct SystemPoint {
    pub ts: DateTime<Utc>,
    pub sample: SysSample,
}

impl Stats {
    pub fn open(path: &Path, providers: &[Provider]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create stats directory {}", parent.display())
                })?;
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed to open stats db at {}", path.display()))?;

        // WAL + NORMAL sync gives us durability across crashes with minimal
        // write amplification — important when health-check writes happen
        // every few seconds per provider.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;\
             PRAGMA synchronous = NORMAL;\
             PRAGMA foreign_keys = ON;",
        )
        .context("failed to set sqlite pragmas")?;

        conn.execute_batch(SCHEMA)
            .context("failed to apply stats schema")?;

        for p in providers {
            conn.execute(
                "INSERT INTO providers(name, gateway, interface, priority, role)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(name) DO UPDATE SET
                     gateway = excluded.gateway,
                     interface = excluded.interface,
                     priority = excluded.priority,
                     role = excluded.role",
                params![
                    p.name,
                    p.gateway.to_string(),
                    p.interface,
                    p.priority,
                    p.role.as_str(),
                ],
            )?;
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn record_health(&self, r: &HealthRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO health_checks(provider, ts, success, latency_ms, kind)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                r.provider,
                r.timestamp.to_rfc3339(),
                r.success as i32,
                r.latency_ms,
                r.kind,
            ],
        )?;
        Ok(())
    }

    pub fn record_failover(&self, r: &FailoverRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO failover_events(ts, from_provider, to_provider, reason)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                r.timestamp.to_rfc3339(),
                r.from_provider,
                r.to_provider,
                r.reason,
            ],
        )?;
        Ok(())
    }

    pub fn record_state_change(&self, provider: &str, state: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO state_changes(ts, provider, state) VALUES(?1, ?2, ?3)",
            params![Utc::now().to_rfc3339(), provider, state],
        )?;
        Ok(())
    }

    pub fn record_traffic(
        &self,
        provider: &str,
        interface: &str,
        ts: DateTime<Utc>,
        interval_s: f64,
        delta: &IfCounters,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO traffic_samples(
                ts, provider, interface, interval_s,
                rx_bytes, rx_packets, tx_bytes, tx_packets
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ts.to_rfc3339(),
                provider,
                interface,
                interval_s,
                delta.rx_bytes as i64,
                delta.rx_packets as i64,
                delta.tx_bytes as i64,
                delta.tx_packets as i64,
            ],
        )?;
        Ok(())
    }

    /// Remove traffic samples older than `retention_hours`. Cheap — the
    /// index on `ts` turns it into a range delete.
    pub fn prune_traffic(&self, retention_hours: u32) -> Result<usize> {
        if retention_hours == 0 {
            return Ok(0);
        }
        let window = format!("-{retention_hours} hours");
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM traffic_samples WHERE ts < datetime('now', ?1)",
            params![window],
        )?;
        Ok(n)
    }

    /// Sum rx/tx bytes+packets per provider over a trailing time window.
    pub fn traffic_totals(&self, hours: u32) -> Result<Vec<TrafficTotals>> {
        let window = format!("-{hours} hours");
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT provider,
                    COALESCE(SUM(rx_bytes), 0),
                    COALESCE(SUM(rx_packets), 0),
                    COALESCE(SUM(tx_bytes), 0),
                    COALESCE(SUM(tx_packets), 0)
             FROM traffic_samples
             WHERE ts >= datetime('now', ?1)
             GROUP BY provider
             ORDER BY provider",
        )?;
        let rows = stmt.query_map(params![window], |row| {
            Ok(TrafficTotals {
                provider: row.get::<_, String>(0)?,
                rx_bytes: row.get::<_, i64>(1)?,
                rx_packets: row.get::<_, i64>(2)?,
                tx_bytes: row.get::<_, i64>(3)?,
                tx_packets: row.get::<_, i64>(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Latest N traffic samples for a single provider, oldest-first. Used
    /// by the TUI to draw sparklines without having to keep in-memory
    /// buffers duplicated between the daemon and the viewer.
    pub fn recent_traffic(&self, provider: &str, limit: u32) -> Result<Vec<TrafficPoint>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts, interval_s, rx_bytes, rx_packets, tx_bytes, tx_packets
             FROM traffic_samples
             WHERE provider = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![provider, limit], |row| {
            let ts_str: String = row.get(0)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(TrafficPoint {
                ts,
                interval_s: row.get(1)?,
                rx_bytes: row.get::<_, i64>(2)? as u64,
                rx_packets: row.get::<_, i64>(3)? as u64,
                tx_bytes: row.get::<_, i64>(4)? as u64,
                tx_packets: row.get::<_, i64>(5)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        out.reverse();
        Ok(out)
    }

    /// Record one system sample. `per_core_json` is `None` when the config
    /// disables per-core storage (saves ~16 bytes/core/sample).
    pub fn record_system(
        &self,
        ts: DateTime<Utc>,
        s: &SysSample,
        store_per_core: bool,
    ) -> Result<()> {
        let per_core_json = if store_per_core {
            Some(serde_json::to_string(&s.cpu_per_core).unwrap_or_else(|_| "[]".into()))
        } else {
            None
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO system_samples(
                ts, cpu_total, cpu_per_core,
                mem_total, mem_used, mem_available,
                swap_total, swap_used,
                load1, load5, load15,
                net_rx_bytes, net_tx_bytes,
                disk_total, disk_used,
                uptime_s, procs
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                ts.to_rfc3339(),
                s.cpu_total as f64,
                per_core_json,
                s.mem_total as i64,
                s.mem_used as i64,
                s.mem_available as i64,
                s.swap_total as i64,
                s.swap_used as i64,
                s.load1,
                s.load5,
                s.load15,
                s.net_rx_bytes as i64,
                s.net_tx_bytes as i64,
                s.disk_total as i64,
                s.disk_used as i64,
                s.uptime_s as i64,
                s.procs as i64,
            ],
        )?;
        Ok(())
    }

    /// Range-delete old system samples. Returns the number of rows removed.
    pub fn prune_system(&self, retention_hours: u32) -> Result<usize> {
        if retention_hours == 0 {
            return Ok(0);
        }
        let window = format!("-{retention_hours} hours");
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM system_samples WHERE ts < datetime('now', ?1)",
            params![window],
        )?;
        Ok(n)
    }

    /// Latest N system samples, oldest-first. The TUI uses this for
    /// CPU/RAM/LOAD sparklines.
    pub fn recent_system(&self, limit: u32) -> Result<Vec<SystemPoint>> {
        let limit = limit.min(10_000);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts, cpu_total, cpu_per_core,
                    mem_total, mem_used, mem_available,
                    swap_total, swap_used,
                    load1, load5, load15,
                    net_rx_bytes, net_tx_bytes,
                    disk_total, disk_used,
                    uptime_s, procs
             FROM system_samples
             ORDER BY id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let ts_str: String = row.get(0)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let per_core_json: Option<String> = row.get(2)?;
            let cpu_per_core: Vec<f32> = per_core_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            Ok(SystemPoint {
                ts,
                sample: SysSample {
                    cpu_total: row.get::<_, f64>(1)? as f32,
                    cpu_per_core,
                    mem_total: row.get::<_, i64>(3)? as u64,
                    mem_used: row.get::<_, i64>(4)? as u64,
                    mem_available: row.get::<_, i64>(5)? as u64,
                    swap_total: row.get::<_, i64>(6)? as u64,
                    swap_used: row.get::<_, i64>(7)? as u64,
                    load1: row.get(8)?,
                    load5: row.get(9)?,
                    load15: row.get(10)?,
                    net_rx_bytes: row.get::<_, i64>(11)? as u64,
                    net_tx_bytes: row.get::<_, i64>(12)? as u64,
                    disk_total: row.get::<_, i64>(13)? as u64,
                    disk_used: row.get::<_, i64>(14)? as u64,
                    uptime_s: row.get::<_, i64>(15)? as u64,
                    procs: row.get::<_, i64>(16)? as u64,
                },
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        out.reverse();
        Ok(out)
    }

    /// Aggregated, human-readable report across the trailing `hours` window.
    /// Used by the `vlb stats` CLI subcommand; the query runs read-only and
    /// does not block probe writers for any meaningful duration.
    pub fn report(&self, hours: u32, recent: u32) -> Result<String> {
        use std::fmt::Write;
        let conn = self.conn.lock().unwrap();
        let window = format!("-{hours} hours");

        let mut s = String::new();
        let _ = writeln!(s, "vlb stats — last {hours}h window");
        let _ = writeln!(s, "{}", "=".repeat(72));

        // Per-provider / per-kind aggregates.
        let mut stmt = conn.prepare(
            "SELECT provider, kind,
                    COUNT(*) AS total,
                    SUM(success) AS ok,
                    ROUND(AVG(CAST(success AS REAL)) * 100, 2) AS pct,
                    ROUND(AVG(latency_ms), 2) AS avg_ms
             FROM health_checks
             WHERE ts >= datetime('now', ?1)
             GROUP BY provider, kind
             ORDER BY provider, kind",
        )?;
        let _ = writeln!(
            s,
            "{:<18} {:<10} {:>8} {:>8} {:>8} {:>10}",
            "provider", "kind", "total", "ok", "pct%", "avg_ms"
        );
        let _ = writeln!(s, "{}", "-".repeat(72));
        let mut rows = stmt.query(params![window])?;
        let mut any_health = false;
        while let Some(row) = rows.next()? {
            any_health = true;
            let provider: String = row.get(0)?;
            let kind: String = row.get(1)?;
            let total: i64 = row.get(2)?;
            let ok: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
            let pct: f64 = row.get::<_, Option<f64>>(4)?.unwrap_or(0.0);
            let avg_ms: Option<f64> = row.get(5)?;
            let avg_str = avg_ms
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "--".into());
            let _ = writeln!(
                s,
                "{provider:<18} {kind:<10} {total:>8} {ok:>8} {pct:>8.2} {avg_str:>10}"
            );
        }
        if !any_health {
            let _ = writeln!(s, "(no health-check samples in window)");
        }

        // Traffic totals per provider over the same window. We have to
        // release the connection lock before calling `traffic_totals`
        // because it re-acquires the same mutex internally.
        drop(rows);
        drop(stmt);
        drop(conn);
        let traffic = self.traffic_totals(hours).unwrap_or_default();
        let _ = writeln!(s);
        let _ = writeln!(s, "traffic totals:");
        let _ = writeln!(s, "{}", "-".repeat(72));
        let _ = writeln!(
            s,
            "{:<18} {:>14} {:>12} {:>14} {:>12}",
            "provider", "rx_bytes", "rx_pkts", "tx_bytes", "tx_pkts"
        );
        if traffic.is_empty() {
            let _ = writeln!(s, "(no traffic samples in window)");
        } else {
            for t in &traffic {
                let _ = writeln!(
                    s,
                    "{:<18} {:>14} {:>12} {:>14} {:>12}",
                    t.provider, t.rx_bytes, t.rx_packets, t.tx_bytes, t.tx_packets
                );
            }
        }

        // System load aggregate over the same window. Cheap single-row query.
        type SysAgg = (f64, f64, f64, f64, f64, f64, i64, i64);
        let sys_agg: Option<SysAgg> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT AVG(cpu_total), MAX(cpu_total),
                        AVG(mem_used),  MAX(mem_used),
                        AVG(load1),     MAX(load1),
                        MAX(mem_total), MAX(swap_used)
                 FROM system_samples
                 WHERE ts >= datetime('now', ?1)",
            )?;
            let mut rows = stmt.query(params![window])?;
            if let Some(row) = rows.next()? {
                let avg_cpu: Option<f64> = row.get(0)?;
                let max_cpu: Option<f64> = row.get(1)?;
                let avg_mem: Option<f64> = row.get(2)?;
                let max_mem: Option<f64> = row.get(3)?;
                let avg_load: Option<f64> = row.get(4)?;
                let max_load: Option<f64> = row.get(5)?;
                let mem_total: Option<i64> = row.get(6)?;
                let max_swap: Option<i64> = row.get(7)?;
                match (
                    avg_cpu, max_cpu, avg_mem, max_mem, avg_load, max_load, mem_total, max_swap,
                ) {
                    (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g), Some(h)) => {
                        Some((a, b, c, d, e, f, g, h))
                    }
                    _ => None,
                }
            } else {
                None
            }
        };
        let _ = writeln!(s);
        let _ = writeln!(s, "system load (btop-style aggregate):");
        let _ = writeln!(s, "{}", "-".repeat(72));
        if let Some((avg_cpu, max_cpu, avg_mem, max_mem, avg_load, max_load, mem_total, max_swap)) =
            sys_agg
        {
            let mem_total_f = mem_total as f64;
            let avg_mem_pct = if mem_total_f > 0.0 {
                avg_mem / mem_total_f * 100.0
            } else {
                0.0
            };
            let max_mem_pct = if mem_total_f > 0.0 {
                max_mem / mem_total_f * 100.0
            } else {
                0.0
            };
            let _ = writeln!(s, "cpu   avg {avg_cpu:>6.2}%  max {max_cpu:>6.2}%");
            let _ = writeln!(
                s,
                "mem   avg {avg_mem_pct:>6.2}%  max {max_mem_pct:>6.2}%  (total {})",
                fmt_bytes_inline(mem_total as u64),
            );
            let _ = writeln!(
                s,
                "load  avg {avg_load:>6.2}   max {max_load:>6.2}   swap_peak {}",
                fmt_bytes_inline(max_swap as u64),
            );
        } else {
            let _ = writeln!(s, "(no system samples in window)");
        }
        let conn = self.conn.lock().unwrap();

        // Recent failovers.
        let _ = writeln!(s);
        let _ = writeln!(s, "recent failovers (last {recent}):");
        let _ = writeln!(s, "{}", "-".repeat(72));
        let mut stmt = conn.prepare(
            "SELECT ts, from_provider, to_provider, reason
             FROM failover_events
             ORDER BY id DESC
             LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![recent])?;
        let mut any_fo = false;
        while let Some(row) = rows.next()? {
            any_fo = true;
            let ts: String = row.get(0)?;
            let from: Option<String> = row.get(1)?;
            let to: String = row.get(2)?;
            let reason: String = row.get(3)?;
            let from_s = from.as_deref().unwrap_or("(none)");
            let _ = writeln!(s, "{ts}  {from_s} -> {to}   {reason}");
        }
        if !any_fo {
            let _ = writeln!(s, "(no failover events recorded)");
        }

        Ok(s)
    }
}

fn fmt_bytes_inline(n: u64) -> String {
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

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS providers (
    name      TEXT PRIMARY KEY,
    gateway   TEXT NOT NULL,
    interface TEXT NOT NULL,
    priority  INTEGER NOT NULL,
    role      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS health_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    provider   TEXT NOT NULL,
    ts         TEXT NOT NULL,
    success    INTEGER NOT NULL,
    latency_ms REAL,
    kind       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_health_provider_ts ON health_checks(provider, ts);
CREATE INDEX IF NOT EXISTS idx_health_ts          ON health_checks(ts);

CREATE TABLE IF NOT EXISTS failover_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    from_provider TEXT,
    to_provider   TEXT NOT NULL,
    reason        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_failover_ts ON failover_events(ts);

CREATE TABLE IF NOT EXISTS state_changes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    provider TEXT NOT NULL,
    state    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_state_provider_ts ON state_changes(provider, ts);

CREATE TABLE IF NOT EXISTS traffic_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    provider    TEXT NOT NULL,
    interface   TEXT NOT NULL,
    interval_s  REAL NOT NULL,
    rx_bytes    INTEGER NOT NULL,
    rx_packets  INTEGER NOT NULL,
    tx_bytes    INTEGER NOT NULL,
    tx_packets  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_provider_ts ON traffic_samples(provider, ts);
CREATE INDEX IF NOT EXISTS idx_traffic_ts          ON traffic_samples(ts);

CREATE TABLE IF NOT EXISTS system_samples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    cpu_total     REAL    NOT NULL,
    cpu_per_core  TEXT,                    -- JSON array of per-core %, optional
    mem_total     INTEGER NOT NULL,
    mem_used      INTEGER NOT NULL,
    mem_available INTEGER NOT NULL,
    swap_total    INTEGER NOT NULL,
    swap_used     INTEGER NOT NULL,
    load1         REAL    NOT NULL,
    load5         REAL    NOT NULL,
    load15        REAL    NOT NULL,
    net_rx_bytes  INTEGER NOT NULL,
    net_tx_bytes  INTEGER NOT NULL,
    disk_total    INTEGER NOT NULL,
    disk_used     INTEGER NOT NULL,
    uptime_s      INTEGER NOT NULL,
    procs         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_ts ON system_samples(ts);

-- Convenience view: per-provider rolling success ratio over last 1h.
CREATE VIEW IF NOT EXISTS provider_health_summary AS
SELECT
    provider,
    COUNT(*)                                   AS total,
    SUM(success)                               AS successes,
    ROUND(AVG(CAST(success AS REAL)) * 100, 2) AS success_pct,
    ROUND(AVG(latency_ms), 2)                  AS avg_latency_ms
FROM health_checks
WHERE ts >= datetime('now', '-1 hour')
GROUP BY provider;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Provider, ProviderRole};
    use std::net::Ipv4Addr;

    fn mk_providers() -> Vec<Provider> {
        vec![Provider {
            name: "p0".into(),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            interface: "eth0".into(),
            priority: 0,
            role: ProviderRole::Primary,
        }]
    }

    #[test]
    fn open_and_record_health_in_tempfile() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-test-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let stats = Stats::open(&tmp, &mk_providers()).unwrap();
        stats
            .record_health(&HealthRecord {
                provider: "p0".into(),
                timestamp: Utc::now(),
                success: true,
                latency_ms: Some(1.2),
                kind: "gateway",
            })
            .unwrap();
        stats
            .record_failover(&FailoverRecord {
                timestamp: Utc::now(),
                from_provider: None,
                to_provider: "p0".into(),
                reason: "bootstrap".into(),
            })
            .unwrap();
        stats.record_state_change("p0", "up").unwrap();
        let report = stats.report(24, 5).unwrap();
        assert!(report.contains("p0"));
        assert!(report.contains("bootstrap"));
        drop(stats);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    #[test]
    fn traffic_roundtrip_and_prune() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-traffic-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let stats = Stats::open(&tmp, &mk_providers()).unwrap();

        let delta = crate::traffic::IfCounters {
            rx_bytes: 1024,
            rx_packets: 8,
            tx_bytes: 2048,
            tx_packets: 16,
        };
        stats
            .record_traffic("p0", "eth0", Utc::now(), 1.0, &delta)
            .unwrap();
        let totals = stats.traffic_totals(1).unwrap();
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].provider, "p0");
        assert_eq!(totals[0].rx_bytes, 1024);
        assert_eq!(totals[0].tx_bytes, 2048);

        let recent = stats.recent_traffic("p0", 10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].rx_bytes, 1024);

        // 0-hour retention is a no-op
        assert_eq!(stats.prune_traffic(0).unwrap(), 0);

        drop(stats);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    #[test]
    fn system_record_and_recent() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-sys-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let stats = Stats::open(&tmp, &mk_providers()).unwrap();
        let sample = SysSample {
            cpu_total: 12.5,
            cpu_per_core: vec![10.0, 15.0],
            mem_total: 1024,
            mem_used: 512,
            mem_available: 512,
            ..Default::default()
        };
        stats.record_system(Utc::now(), &sample, true).unwrap();
        let recent = stats.recent_system(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert!((recent[0].sample.cpu_total - 12.5).abs() < 0.001);
        assert_eq!(recent[0].sample.cpu_per_core, vec![10.0, 15.0]);

        drop(stats);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }
}
