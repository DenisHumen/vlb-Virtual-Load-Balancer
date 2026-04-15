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
