//! Control plane for the running balancer.
//!
//! A tiny line-delimited JSON protocol over localhost TCP. Every connection
//! sends one request line and receives one response line, then the server
//! closes. That keeps the server stateless and makes it trivial to drive
//! from shell (`nc`), from the `vlb` CLI (`vlb status`, `vlb force …`) and
//! from the built-in TUI.
//!
//! There is no authentication — binding is to `127.0.0.1` by default and it
//! is the operator's responsibility not to expose it externally. That is
//! called out explicitly in the config doc.
//!
//! # Requests
//!
//! ```json
//! {"op": "status"}
//! {"op": "force", "provider": "isp-main"}
//! {"op": "auto"}
//! {"op": "traffic", "provider": "isp-main", "limit": 120}  // optional, for graphs
//! ```
//!
//! # Responses
//!
//! `{"ok": true, ...}` or `{"ok": false, "error": "..."}`.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tracing::{debug, error, info, warn};

use crate::balancer::{Balancer, ControlSnapshot};
use crate::sysmon::SysSample;

/// Hard cap on simultaneous control-plane clients. The protocol is
/// unauthenticated and bound to loopback, but we still enforce a ceiling so
/// a buggy/runaway local client cannot exhaust our task budget.
const MAX_CONCURRENT_CONNS: usize = 32;

/// Hard cap on the size of a single request line. 64 KiB is generous for
/// any legitimate JSON request we accept (the largest is `Traffic` with a
/// provider name and an integer). The cap prevents a malicious client from
/// streaming infinite data to exhaust memory.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Per-connection read timeout. A well-behaved client sends one line and
/// closes; anything longer indicates a slowloris attempt or a hung peer.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    /// Live snapshot: providers, active, forced override, timings.
    Status,
    /// Pin the active provider to the given name. Ignored if the provider
    /// is currently DOWN — the pin will be applied as soon as it recovers.
    Force { provider: String },
    /// Release the manual pin and return to automatic priority-based selection.
    Auto,
    /// Recent traffic samples for graph rendering.
    Traffic {
        provider: String,
        #[serde(default = "default_limit")]
        limit: u32,
    },
    /// Recent system samples (CPU/RAM/load) for the btop-style TUI.
    System {
        #[serde(default = "default_limit")]
        limit: u32,
    },
}

fn default_limit() -> u32 { 120 }

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Response {
    Status { snapshot: ControlSnapshot },
    Ok { message: String },
    Traffic { points: Vec<TrafficPointWire> },
    System { points: Vec<SystemPointWire> },
    Error { error: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrafficPointWire {
    pub ts: String,
    pub interval_s: f64,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemPointWire {
    pub ts: String,
    pub sample: SysSample,
}

pub async fn serve(
    listen: String,
    balancer: Arc<Balancer>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %listen, error = %e, "control server: bind failed");
            return;
        }
    };
    info!(addr = %listen, "control server listening");

    // Cap simultaneous clients. `Semaphore` is cheap and lets us back-pressure
    // before spawning a task, so a flood cannot explode our task count.
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        // Reject non-loopback peers defensively. `Config::validate`
                        // already refuses non-loopback binds, but this is a cheap
                        // second line of defence in case the config guard is ever
                        // relaxed.
                        if !peer.ip().is_loopback() {
                            warn!(%peer, "control: rejecting non-loopback peer");
                            drop(stream);
                            continue;
                        }
                        let permit = match Arc::clone(&sem).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!(%peer, "control: connection limit reached, dropping");
                                drop(stream);
                                continue;
                            }
                        };
                        debug!(%peer, "control: accepted");
                        let b = Arc::clone(&balancer);
                        tokio::spawn(async move {
                            let _permit = permit; // released on drop
                            if let Err(e) = handle(stream, b).await {
                                warn!(%peer, error = %e, "control: connection error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "control: accept failed");
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("control server stopping");
                    return;
                }
            }
        }
    }
}

async fn handle(stream: TcpStream, balancer: Arc<Balancer>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    // Hard cap on read volume. `take` enforces it at the byte level, so a
    // slowloris-style attacker cannot keep feeding us data without ever
    // terminating the line.
    let mut reader = BufReader::new(reader.take(MAX_REQUEST_BYTES));
    let mut line = String::new();
    let read = tokio::time::timeout(READ_TIMEOUT, reader.read_line(&mut line)).await;
    let n = match read {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            // Timeout: write an error and bail.
            let resp = Response::Error { error: "request timed out".into() };
            let body = serde_json::to_string(&resp)?;
            writer.write_all(body.as_bytes()).await.ok();
            writer.write_all(b"\n").await.ok();
            return Ok(());
        }
    };
    if n == 0 {
        return Ok(());
    }

    let response: Response = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => dispatch(req, &balancer).await,
        Err(e) => Response::Error { error: format!("invalid request: {e}") },
    };

    let body = serde_json::to_string(&response)?;
    writer.write_all(body.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await.ok();
    Ok(())
}

async fn dispatch(req: Request, balancer: &Arc<Balancer>) -> Response {
    match req {
        Request::Status => Response::Status { snapshot: balancer.snapshot().await },
        Request::Force { provider } => match balancer.force_provider(&provider).await {
            Ok(()) => Response::Ok { message: format!("forced provider = {provider}") },
            Err(e) => Response::Error { error: e.to_string() },
        },
        Request::Auto => {
            balancer.clear_force().await;
            Response::Ok { message: "automatic selection restored".into() }
        }
        Request::Traffic { provider, limit } => {
            match balancer.recent_traffic(&provider, limit) {
                Ok(points) => Response::Traffic {
                    points: points
                        .into_iter()
                        .map(|p| TrafficPointWire {
                            ts: p.ts.to_rfc3339(),
                            interval_s: p.interval_s,
                            rx_bytes: p.rx_bytes,
                            rx_packets: p.rx_packets,
                            tx_bytes: p.tx_bytes,
                            tx_packets: p.tx_packets,
                        })
                        .collect(),
                },
                Err(e) => Response::Error { error: e.to_string() },
            }
        }
        Request::System { limit } => match balancer.recent_system(limit) {
            Ok(points) => Response::System {
                points: points
                    .into_iter()
                    .map(|p| SystemPointWire {
                        ts: p.ts.to_rfc3339(),
                        sample: p.sample,
                    })
                    .collect(),
            },
            Err(e) => Response::Error { error: e.to_string() },
        },
    }
}

/// Simple blocking client used by the CLI (`vlb status`, `vlb force`, ...)
/// and by the TUI. One request, one response, one close.
pub async fn send(listen: &str, req: &Request) -> Result<Response> {
    let io_timeout = std::time::Duration::from_secs(5);
    let mut stream = tokio::time::timeout(io_timeout, TcpStream::connect(listen))
        .await
        .map_err(|_| anyhow::anyhow!("connect to {listen} timed out"))??;
    let body = serde_json::to_string(req)?;
    tokio::time::timeout(io_timeout, async {
        stream.write_all(body.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.shutdown().await.ok();
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("write to {listen} timed out"))??;

    let mut buf = String::new();
    let mut reader = BufReader::new(stream.take(MAX_REQUEST_BYTES * 16));
    tokio::time::timeout(io_timeout, reader.read_line(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("read from {listen} timed out"))??;
    let resp: Response = serde_json::from_str(buf.trim())?;
    Ok(resp)
}

// Request is Serialize too for the client side.
impl Serialize for Request {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut m = serializer.serialize_map(None)?;
        match self {
            Request::Status => {
                m.serialize_entry("op", "status")?;
            }
            Request::System { limit } => {
                m.serialize_entry("op", "system")?;
                m.serialize_entry("limit", limit)?;
            }
            Request::Force { provider } => {
                m.serialize_entry("op", "force")?;
                m.serialize_entry("provider", provider)?;
            }
            Request::Auto => {
                m.serialize_entry("op", "auto")?;
            }
            Request::Traffic { provider, limit } => {
                m.serialize_entry("op", "traffic")?;
                m.serialize_entry("provider", provider)?;
                m.serialize_entry("limit", limit)?;
            }
        }
        m.end()
    }
}
