use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

use crate::config::Provider;

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

        conn.execute_batch(SCHEMA).context("failed to apply stats schema")?;

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

        Ok(Self { conn: Mutex::new(conn) })
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
}
