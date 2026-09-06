use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use crate::clients::ClientCounters;
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
    pub kind: &'static str, // gateway | internet | dns | dns_integrity | canary
}

#[derive(Debug, Clone)]
pub struct FailoverRecord {
    pub timestamp: DateTime<Utc>,
    pub from_provider: Option<String>,
    pub to_provider: String,
    pub reason: String,
}

/// One row of `failover_events`, as read back for the TUI and the control
/// protocol.
#[derive(Debug, Clone)]
pub struct FailoverEvent {
    pub ts: DateTime<Utc>,
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

/// A LAN client as the database remembers it, independent of whether it is
/// connected right now.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub label: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// One persisted traffic bucket for a client.
#[derive(Debug, Clone)]
pub struct ClientSamplePoint {
    pub ts: DateTime<Utc>,
    pub interval_s: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// A period during which a client was continuously present.
#[derive(Debug, Clone)]
pub struct ClientSessionRow {
    pub id: i64,
    pub ip: String,
    pub started_at: DateTime<Utc>,
    /// `None` while the session is still open.
    pub ended_at: Option<DateTime<Utc>>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

impl ClientSessionRow {
    /// How long the session lasted, measured to `now` while it is open.
    pub fn duration_secs(&self, now: DateTime<Utc>) -> i64 {
        let end = self.ended_at.unwrap_or(now);
        (end - self.started_at).num_seconds().max(0)
    }
}

/// Per-client aggregates over a time window.
#[derive(Debug, Clone, Default)]
pub struct ClientRollup {
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    /// Sessions that ended inside the window — every one of them is a moment
    /// this client dropped off the LAN.
    pub disconnects: i64,
    /// Seconds the client was present inside the window.
    pub online_secs: i64,
}

impl Stats {
    pub fn open(path: &Path, providers: &[Provider]) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create stats directory {}", parent.display())
            })?;
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

    // ── small durable key/value store ───────────────────────────────────
    //
    // For the handful of facts that must outlive a restart: the operator's
    // pin, chiefly. An update restarts the daemon, and an operator who pinned
    // a provider an hour ago does not expect the pin to evaporate because a
    // new release came out.

    pub fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO kv(key, value, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                            updated_at = excluded.updated_at",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_kv(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM kv WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    pub fn del_kv(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Timestamps of real switchovers since `since`, newest first.
    ///
    /// "Real" excludes the initial selection (no `from`) and the watchdog's
    /// re-installs (`from == to`): neither is a flap. Used to rebuild the
    /// flap tracker after a restart, so a bouncing uplink cannot reset its
    /// own backoff by having the daemon restarted.
    pub fn failover_times_since(
        &self,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<DateTime<Utc>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts FROM failover_events
             WHERE ts >= ?1
               AND from_provider IS NOT NULL
               AND from_provider != to_provider
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since.to_rfc3339(), limit], |row| {
            let ts: String = row.get(0)?;
            Ok(ts)
        })?;
        let mut out = Vec::new();
        for r in rows {
            if let Ok(t) = DateTime::parse_from_rfc3339(&r?) {
                out.push(t.with_timezone(&Utc));
            }
        }
        Ok(out)
    }

    /// The most recent failover events, newest first.
    pub fn recent_failovers(&self, limit: u32) -> Result<Vec<FailoverEvent>> {
        let limit = limit.min(1_000);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts, from_provider, to_provider, reason
             FROM failover_events
             ORDER BY id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let ts_str: String = row.get(0)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(FailoverEvent {
                ts,
                from_provider: row.get(1)?,
                to_provider: row.get(2)?,
                reason: row.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ── LAN clients ─────────────────────────────────────────────────────
    //
    // Three tables, each answering a different question: `clients` is the
    // roster (who has ever been here, and what do we call them),
    // `client_sessions` is presence (when were they connected, and when did
    // they drop), `client_samples` is volume (how much did they move, and
    // when). Keeping them apart is what lets an idle client cost nothing:
    // presence is two rows per connection, not one per tick.

    /// Record a client, or update what we know about it.
    ///
    /// Discovered facts never overwrite themselves with nothing: a client
    /// whose DHCP lease has expired keeps the hostname it had, because
    /// "we no longer know" is less useful to an operator than "it was this".
    pub fn upsert_client(
        &self,
        ip: &str,
        mac: Option<&str>,
        hostname: Option<&str>,
        label: Option<&str>,
        seen_at: DateTime<Utc>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO clients(ip, mac, hostname, label, first_seen, last_seen)
             VALUES(?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(ip) DO UPDATE SET
                 mac       = COALESCE(excluded.mac, clients.mac),
                 hostname  = COALESCE(excluded.hostname, clients.hostname),
                 label     = excluded.label,
                 last_seen = excluded.last_seen",
            params![ip, mac, hostname, label, seen_at.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Persist one accumulated traffic bucket for a client.
    pub fn record_client_sample(
        &self,
        ip: &str,
        ts: DateTime<Utc>,
        interval_s: f64,
        c: &ClientCounters,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO client_samples(ts, ip, interval_s, rx_bytes, rx_packets, tx_bytes, tx_packets)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ts.to_rfc3339(),
                ip,
                interval_s,
                c.rx_bytes as i64,
                c.rx_packets as i64,
                c.tx_bytes as i64,
                c.tx_packets as i64,
            ],
        )?;
        Ok(())
    }

    /// Open a presence session and return its id.
    pub fn open_client_session(&self, ip: &str, at: DateTime<Utc>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO client_sessions(ip, started_at) VALUES(?1, ?2)",
            params![ip, at.to_rfc3339()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Close a presence session at the moment the client was last seen.
    pub fn close_client_session(&self, id: i64, at: DateTime<Utc>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE client_sessions SET ended_at = ?2 WHERE id = ?1 AND ended_at IS NULL",
            params![id, at.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Add traffic to a session's running totals.
    pub fn add_session_bytes(&self, id: i64, rx: u64, tx: u64) -> Result<()> {
        if rx == 0 && tx == 0 {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE client_sessions
                SET rx_bytes = rx_bytes + ?2, tx_bytes = tx_bytes + ?3
              WHERE id = ?1",
            params![id, rx as i64, tx as i64],
        )?;
        Ok(())
    }

    /// Sessions left open by a previous run.
    ///
    /// A restart is not a disconnection — the routes stay up and the clients
    /// never notice — so these are handed back to the new process to either
    /// continue or close honestly.
    pub fn open_client_sessions(&self) -> Result<Vec<ClientSessionRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ip, started_at, ended_at, rx_bytes, tx_bytes
               FROM client_sessions WHERE ended_at IS NULL",
        )?;
        let rows = stmt.query_map([], map_session)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Everything in the roster, most recently seen first.
    pub fn clients(&self) -> Result<Vec<ClientRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, mac, hostname, label, first_seen, last_seen
               FROM clients ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ClientRow {
                ip: row.get(0)?,
                mac: row.get(1)?,
                hostname: row.get(2)?,
                label: row.get(3)?,
                first_seen: parse_ts(row.get::<_, String>(4)?),
                last_seen: parse_ts(row.get::<_, String>(5)?),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Traffic, disconnections and connected time per client over a window.
    ///
    /// One query for the bytes and one for the sessions, rather than one per
    /// client: the dashboard refreshes this every couple of seconds, and a
    /// query per row would turn a twenty-host LAN into forty round trips.
    pub fn client_rollup(
        &self,
        hours: u32,
        now: DateTime<Utc>,
    ) -> Result<HashMap<String, ClientRollup>> {
        let cutoff = now - chrono::Duration::hours(hours.max(1) as i64);
        let cutoff_s = cutoff.to_rfc3339();
        let mut out: HashMap<String, ClientRollup> = HashMap::new();

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, COALESCE(SUM(rx_bytes),0), COALESCE(SUM(tx_bytes),0)
               FROM client_samples WHERE ts >= ?1 GROUP BY ip",
        )?;
        let mut rows = stmt.query(params![cutoff_s])?;
        while let Some(row) = rows.next()? {
            let e = out.entry(row.get::<_, String>(0)?).or_default();
            e.rx_bytes = row.get(1)?;
            e.tx_bytes = row.get(2)?;
        }
        drop(rows);
        drop(stmt);

        // Sessions that touch the window at all: still open, or ended inside
        // it. Overlap is computed here rather than in SQL because clamping
        // two timestamps to a window is far clearer in Rust than in
        // julianday arithmetic.
        let mut stmt = conn.prepare(
            "SELECT ip, started_at, ended_at
               FROM client_sessions
              WHERE ended_at IS NULL OR ended_at >= ?1",
        )?;
        let mut rows = stmt.query(params![cutoff_s])?;
        while let Some(row) = rows.next()? {
            let ip: String = row.get(0)?;
            let started = parse_ts(row.get::<_, String>(1)?);
            let ended: Option<String> = row.get(2)?;
            let ended = ended.map(parse_ts);
            let e = out.entry(ip).or_default();
            let from = started.max(cutoff);
            let to = ended.unwrap_or(now).min(now);
            if to > from {
                e.online_secs += (to - from).num_seconds();
            }
            if ended.is_some() {
                e.disconnects += 1;
            }
        }
        Ok(out)
    }

    /// Traffic buckets for one client, oldest first — the detail chart.
    pub fn client_samples(
        &self,
        ip: &str,
        hours: u32,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<Vec<ClientSamplePoint>> {
        let cutoff = now - chrono::Duration::hours(hours.max(1) as i64);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts, interval_s, rx_bytes, tx_bytes
               FROM client_samples
              WHERE ip = ?1 AND ts >= ?2
              ORDER BY id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![ip, cutoff.to_rfc3339(), limit.min(5_000)], |row| {
            Ok(ClientSamplePoint {
                ts: parse_ts(row.get::<_, String>(0)?),
                interval_s: row.get(1)?,
                rx_bytes: row.get::<_, i64>(2)? as u64,
                tx_bytes: row.get::<_, i64>(3)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        out.reverse();
        Ok(out)
    }

    /// Recent presence sessions for one client, newest first.
    pub fn client_sessions(&self, ip: &str, limit: u32) -> Result<Vec<ClientSessionRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ip, started_at, ended_at, rx_bytes, tx_bytes
               FROM client_sessions WHERE ip = ?1
              ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ip, limit.min(1_000)], map_session)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Drop client history older than the retention window.
    ///
    /// Sessions and samples go; the roster row stays, so a machine that
    /// reappears after a holiday is still recognised rather than looking new.
    pub fn prune_clients(&self, retention_hours: u32) -> Result<usize> {
        if retention_hours == 0 {
            return Ok(0);
        }
        let cutoff = (Utc::now() - chrono::Duration::hours(retention_hours as i64)).to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let mut n = conn.execute(
            "DELETE FROM client_samples WHERE ts < ?1",
            params![cutoff.clone()],
        )?;
        n += conn.execute(
            "DELETE FROM client_sessions WHERE ended_at IS NOT NULL AND ended_at < ?1",
            params![cutoff],
        )?;
        Ok(n)
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

    /// Delete `health_checks` rows older than `retention_hours`.
    ///
    /// This table is by far the fastest-growing one: every provider writes a
    /// row per probe kind on every tick. At the default 3 s interval with
    /// five kinds and three providers that is roughly 43 M rows a year, on a
    /// box that is expected to run untouched for years. `0` keeps everything.
    pub fn prune_health(&self, retention_hours: u32) -> Result<usize> {
        if retention_hours == 0 {
            return Ok(0);
        }
        let cutoff = Utc::now() - chrono::Duration::hours(retention_hours as i64);
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM health_checks WHERE ts < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        Ok(n)
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
                crate::format::bytes(mem_total as u64),
            );
            let _ = writeln!(
                s,
                "load  avg {avg_load:>6.2}   max {max_load:>6.2}   swap_peak {}",
                crate::format::bytes(max_swap as u64),
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

/// Timestamps are stored as RFC 3339 text. A row that somehow holds
/// something else is not worth failing a whole query over — the alternative
/// is a dashboard that goes blank because of one bad row — so it reads as
/// "now" and the caller sees a point out of place rather than an error.
fn parse_ts(raw: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&raw)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn map_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<ClientSessionRow> {
    let ended: Option<String> = row.get(3)?;
    Ok(ClientSessionRow {
        id: row.get(0)?,
        ip: row.get(1)?,
        started_at: parse_ts(row.get::<_, String>(2)?),
        ended_at: ended.map(parse_ts),
        rx_bytes: row.get(4)?,
        tx_bytes: row.get(5)?,
    })
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

-- ── LAN clients ───────────────────────────────────────────────────────
-- The roster: every host ever seen behind this gateway.
CREATE TABLE IF NOT EXISTS clients (
    ip         TEXT PRIMARY KEY,
    mac        TEXT,
    hostname   TEXT,          -- discovered (DHCP lease, /etc/hosts, PTR)
    label      TEXT,          -- assigned by the operator in the config
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);

-- Presence: one row per continuous connection, so a gap between rows is
-- exactly a disconnection and needs no inference.
CREATE TABLE IF NOT EXISTS client_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at   TEXT,          -- NULL while the client is still connected
    rx_bytes   INTEGER NOT NULL DEFAULT 0,
    tx_bytes   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_client_sessions_ip  ON client_sessions(ip, started_at);
CREATE INDEX IF NOT EXISTS idx_client_sessions_end ON client_sessions(ended_at);

-- Volume: accumulated traffic buckets. Only non-empty buckets are written,
-- so an idle client costs nothing to keep.
CREATE TABLE IF NOT EXISTS client_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    ip         TEXT NOT NULL,
    interval_s REAL NOT NULL,
    rx_bytes   INTEGER NOT NULL,
    rx_packets INTEGER NOT NULL,
    tx_bytes   INTEGER NOT NULL,
    tx_packets INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_client_samples_ip_ts ON client_samples(ip, ts);
CREATE INDEX IF NOT EXISTS idx_client_samples_ts    ON client_samples(ts);

-- Durable odds and ends that must survive a restart (the operator pin).
CREATE TABLE IF NOT EXISTS kv (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

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

    fn counters(rx: u64, rxp: u64, tx: u64, txp: u64) -> ClientCounters {
        ClientCounters {
            rx_bytes: rx,
            rx_packets: rxp,
            tx_bytes: tx,
            tx_packets: txp,
        }
    }

    fn mk_providers() -> Vec<Provider> {
        vec![Provider {
            name: "p0".into(),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            interface: "eth0".into(),
            priority: 0,
            role: ProviderRole::Primary,
        }]
    }

    /// `health_checks` is the fastest-growing table by a wide margin — every
    /// provider writes a row per probe kind on every tick, which is tens of
    /// millions of rows a year on a gateway that is never restarted. It had
    /// no retention at all until this was added, so the pruning is worth
    /// pinning down: old rows go, recent rows stay, and `0` means "keep
    /// everything" rather than "delete everything".
    #[test]
    fn health_rows_are_pruned_by_retention() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-prune-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let stats = Stats::open(&tmp, &mk_providers()).unwrap();

        let now = Utc::now();
        for (age_hours, kind) in [
            (100i64, "gateway"),
            (80, "canary"),
            (1, "dns"),
            (0, "canary"),
        ] {
            stats
                .record_health(&HealthRecord {
                    provider: "p0".into(),
                    timestamp: now - chrono::Duration::hours(age_hours),
                    success: true,
                    latency_ms: None,
                    kind,
                })
                .unwrap();
        }

        let count = || -> i64 {
            stats
                .conn
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM health_checks", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(), 4);

        // 0 must be a no-op, not a wipe.
        assert_eq!(stats.prune_health(0).unwrap(), 0);
        assert_eq!(count(), 4);

        // 72 h retention drops the 100 h and 80 h rows only.
        assert_eq!(stats.prune_health(72).unwrap(), 2);
        assert_eq!(count(), 2);

        // Running it again is idempotent.
        assert_eq!(stats.prune_health(72).unwrap(), 0);
        assert_eq!(count(), 2);

        drop(stats);
        let _ = std::fs::remove_file(&tmp);
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

    /// The pin is the one piece of operator intent the daemon holds, and it
    /// has to come back after an update restarts the process.
    #[test]
    fn kv_roundtrip_survives_reopen() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-kv-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        {
            let stats = Stats::open(&tmp, &mk_providers()).unwrap();
            assert_eq!(stats.get_kv("forced_provider").unwrap(), None);
            stats.set_kv("forced_provider", "isp-backup").unwrap();
            // Overwrite, not duplicate.
            stats.set_kv("forced_provider", "isp-main").unwrap();
        }
        {
            // A fresh process: the value must still be there.
            let stats = Stats::open(&tmp, &mk_providers()).unwrap();
            assert_eq!(
                stats.get_kv("forced_provider").unwrap().as_deref(),
                Some("isp-main")
            );
            stats.del_kv("forced_provider").unwrap();
            assert_eq!(stats.get_kv("forced_provider").unwrap(), None);
            // Deleting a missing key is not an error.
            stats.del_kv("forced_provider").unwrap();
        }
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    /// The client tables answer three separate questions and must keep doing
    /// so: who is known, when were they connected, and how much did they
    /// move. This walks one client through a connection, a drop and a
    /// reconnection, and checks the rollup an operator reads off the
    /// dashboard.
    #[test]
    fn client_roster_sessions_and_rollup() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-clients-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let stats = Stats::open(&tmp, &mk_providers()).unwrap();
        let now = Utc::now();
        let ago = |m: i64| now - chrono::Duration::minutes(m);

        // First connection: 60 min ago, dropped 40 min ago.
        stats
            .upsert_client("10.0.0.50", Some("aa:bb:cc:dd:ee:ff"), None, None, ago(60))
            .unwrap();
        let s1 = stats.open_client_session("10.0.0.50", ago(60)).unwrap();
        stats.add_session_bytes(s1, 1_000, 200).unwrap();
        stats
            .record_client_sample("10.0.0.50", ago(50), 60.0, &counters(1_000, 10, 200, 5))
            .unwrap();
        stats.close_client_session(s1, ago(40)).unwrap();

        // A hostname turns up later; the MAC is not re-sent. Neither fact
        // may erase the other.
        stats
            .upsert_client("10.0.0.50", None, Some("denis-pc"), None, ago(20))
            .unwrap();
        let s2 = stats.open_client_session("10.0.0.50", ago(20)).unwrap();
        stats.add_session_bytes(s2, 3_000, 400).unwrap();
        stats
            .record_client_sample("10.0.0.50", ago(10), 60.0, &counters(3_000, 30, 400, 8))
            .unwrap();

        let roster = stats.clients().unwrap();
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].hostname.as_deref(), Some("denis-pc"));
        assert_eq!(roster[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert!(roster[0].first_seen < roster[0].last_seen);

        let roll = stats.client_rollup(24, now).unwrap();
        let c = &roll["10.0.0.50"];
        assert_eq!(c.rx_bytes, 4_000);
        assert_eq!(c.tx_bytes, 600);
        assert_eq!(c.disconnects, 1, "one session ended inside the window");
        // 20 minutes of the first session plus 20 of the open one.
        assert!(
            (c.online_secs - 40 * 60).abs() < 90,
            "online_secs = {}",
            c.online_secs
        );

        // A one-hour window still sees both sessions; the still-open one is
        // measured to `now`.
        let sessions = stats.client_sessions("10.0.0.50", 10).unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(sessions[0].ended_at.is_none(), "newest first, still open");
        assert!(sessions[0].duration_secs(now) >= 20 * 60 - 2);
        assert_eq!(sessions[1].duration_secs(now), 20 * 60);

        // Restart continuity: the open session is handed back, not lost.
        let open = stats.open_client_sessions().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, s2);

        let samples = stats.client_samples("10.0.0.50", 24, 100, now).unwrap();
        assert_eq!(samples.len(), 2);
        assert!(samples[0].ts < samples[1].ts, "oldest first for charting");

        // Retention drops history but keeps the roster: a machine that
        // reappears after a holiday is not a stranger.
        //
        // Something genuinely old to prune, alongside the recent rows that
        // must survive it.
        stats
            .record_client_sample("10.0.0.50", ago(600), 60.0, &counters(9, 1, 9, 1))
            .unwrap();
        let old = stats.open_client_session("10.0.0.50", ago(700)).unwrap();
        stats.close_client_session(old, ago(600)).unwrap();

        assert_eq!(
            stats.prune_clients(0).unwrap(),
            0,
            "0 means keep everything"
        );
        let removed = stats.prune_clients(1).unwrap();
        assert_eq!(
            removed, 2,
            "the ten-hour-old sample and session, and only those"
        );
        assert_eq!(
            stats
                .client_samples("10.0.0.50", 24, 100, now)
                .unwrap()
                .len(),
            2,
            "rows inside the retention window stay"
        );
        assert_eq!(
            stats.client_sessions("10.0.0.50", 10).unwrap().len(),
            2,
            "and so do their sessions"
        );
        // An open session is never pruned, however long it has been running.
        assert_eq!(stats.open_client_sessions().unwrap().len(), 1);
        // The roster itself is untouched.
        assert_eq!(stats.clients().unwrap().len(), 1);

        drop(stats);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("db-wal"));
        let _ = std::fs::remove_file(tmp.with_extension("db-shm"));
    }

    /// Flap history is rebuilt from `failover_events` after a restart. Only
    /// genuine switches may count: the initial selection has no `from`, and a
    /// watchdog re-install goes from a provider to itself.
    #[test]
    fn failover_history_counts_only_real_switches() {
        let tmp = std::env::temp_dir().join(format!(
            "vlb-flap-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let stats = Stats::open(&tmp, &mk_providers()).unwrap();
        let now = Utc::now();
        let rec = |age_s: i64, from: Option<&str>, to: &str| FailoverRecord {
            timestamp: now - chrono::Duration::seconds(age_s),
            from_provider: from.map(String::from),
            to_provider: to.into(),
            reason: "test".into(),
        };
        stats.record_failover(&rec(500, None, "a")).unwrap(); // initial
        stats.record_failover(&rec(400, Some("a"), "b")).unwrap(); // real
        stats.record_failover(&rec(300, Some("b"), "b")).unwrap(); // watchdog
        stats.record_failover(&rec(200, Some("b"), "a")).unwrap(); // real
        stats.record_failover(&rec(5000, Some("a"), "b")).unwrap(); // too old

        let since = now - chrono::Duration::seconds(1000);
        let times = stats.failover_times_since(since, 256).unwrap();
        assert_eq!(times.len(), 2, "{times:?}");
        // Newest first.
        assert!(times[0] > times[1]);

        let recent = stats.recent_failovers(3).unwrap();
        assert_eq!(recent.len(), 3);
        // Newest first: the 200 s-old one was inserted last.
        assert_eq!(recent[0].to_provider, "b");
        assert_eq!(recent[0].from_provider.as_deref(), Some("a"));

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
