//! LAN client discovery and per-client traffic accounting.
//!
//! # What this answers
//!
//! "Who is behind this gateway, how much have they moved, and were they
//! actually connected the whole time?" — the questions an operator asks when
//! somebody says the internet was slow at four o'clock.
//!
//! # How the bytes are counted
//!
//! Per-client byte counts come from the kernel, not from sampling flows. We
//! keep one iptables chain, [`CHAIN`], hooked into `FORWARD`, holding two
//! *counting* rules per client — a rule with no `-j` target counts the
//! packets that match it and falls through, which is exactly what we want:
//!
//! ```text
//! -A VLB_CLIENTS -d 10.0.0.50/32 -m comment --comment "vlb:dl:10.0.0.50"
//! -A VLB_CLIENTS -s 10.0.0.50/32 -m comment --comment "vlb:ul:10.0.0.50"
//! ```
//!
//! Only forwarded traffic traverses `FORWARD`, so these count precisely what
//! the client sent through the gateway and what came back to it — not the
//! gateway's own probes, and not LAN-local chatter that never reaches us.
//! NAT does not get in the way: MASQUERADE happens later, in `POSTROUTING`,
//! and replies are un-NATed before `FORWARD`, so the client's own address is
//! visible in both directions.
//!
//! The counters are monotonic, so a delta between two reads is the traffic in
//! that interval — the same shape as `/proc/net/dev` sampling in
//! [`crate::traffic`], and it survives conntrack entries expiring, which a
//! flow-based count would not.
//!
//! The comment on each rule is what makes the read robust: we locate rules by
//! their `vlb:` tag rather than by position, so an operator's own rules in
//! `FORWARD` can come and go without confusing us.
//!
//! # How presence is decided
//!
//! From the kernel's neighbour (ARP) table, with an active nudge. A host that
//! has been quiet for half a minute goes `STALE` in the ARP cache, which is
//! indistinguishable from a host that has left — so silence alone would show
//! every idle laptop as disconnected. Instead we ping stale neighbours
//! occasionally: even a host that drops ICMP has to answer the ARP request
//! that precedes it, and that answer is what refreshes the entry. Presence is
//! then "seen recently", with the caller applying its own grace period.
//!
//! # One deliberate gap
//!
//! A host is counted from the moment it is *discovered*, not retroactively.
//! Its rules are installed on the first tick that sees it in the neighbour
//! table, so a host nobody has ever seen before can move up to one sampling
//! interval's worth of traffic uncounted. Closing that would mean counting
//! every address on the segment in advance, which is how a ruleset grows
//! without bound on a network that has a guest wifi.
//!
//! It only ever applies once per host: the rules stay in the chain when a
//! client goes quiet — and across daemon restarts, since nothing is torn
//! down — so a returning laptop is counted from its first packet.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// The iptables chain holding our counting rules.
pub const CHAIN: &str = "VLB_CLIENTS";

/// Rule-comment prefixes. Traffic *to* the client is `dl` (download from the
/// client's point of view), traffic *from* the client is `ul`.
const TAG_DL: &str = "vlb:dl:";
const TAG_UL: &str = "vlb:ul:";

/// How often a stale neighbour is nudged with a ping to refresh its ARP
/// entry. Low enough to keep presence honest, high enough to be invisible.
const PRESENCE_PROBE_EVERY: Duration = Duration::from_secs(30);

/// Ceiling on concurrent presence probes per tick, so a large LAN cannot turn
/// a sampling tick into a burst of a hundred pings.
const MAX_PROBES_PER_TICK: usize = 8;

/// How many newly-discovered clients get their accounting rules per tick.
///
/// Each one is two `iptables` invocations, each taking the xtables lock. A
/// gateway that meets its whole LAN at once — the first tick after a start —
/// would otherwise spend seconds in that loop, and everything asking the
/// daemon a question during it waits.
const MAX_NEW_RULES_PER_TICK: usize = 8;

/// Cumulative counters for one client, as the kernel reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientCounters {
    /// Bytes towards the client (its download).
    pub rx_bytes: u64,
    pub rx_packets: u64,
    /// Bytes from the client (its upload).
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl ClientCounters {
    /// Difference between two cumulative reads, or `None` when the counters
    /// went backwards — a rule was re-created, so the interval is unknowable
    /// and the honest thing is to skip it rather than emit a spike.
    pub fn delta(prev: Self, curr: Self) -> Option<Self> {
        Some(Self {
            rx_bytes: curr.rx_bytes.checked_sub(prev.rx_bytes)?,
            rx_packets: curr.rx_packets.checked_sub(prev.rx_packets)?,
            tx_bytes: curr.tx_bytes.checked_sub(prev.tx_bytes)?,
            tx_packets: curr.tx_packets.checked_sub(prev.tx_packets)?,
        })
    }

    pub fn is_zero(&self) -> bool {
        self.rx_bytes == 0 && self.tx_bytes == 0 && self.rx_packets == 0 && self.tx_packets == 0
    }
}

/// A neighbour as `ip neigh` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    /// The kernel has confirmed this host recently.
    pub reachable: bool,
    /// The entry exists with a hardware address but has not been confirmed
    /// lately — the host may be present and simply quiet.
    pub stale: bool,
}

/// One client, observed over one sampling interval.
#[derive(Debug, Clone)]
pub struct ClientObservation {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    /// Traffic during this interval. Zero is normal and not the same as
    /// absent.
    pub delta: ClientCounters,
    /// The kernel confirmed the host, or it moved bytes this interval.
    pub seen: bool,
}

/// An IPv4 network, used to decide which neighbours are LAN clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        if self.prefix > 32 {
            return false;
        }
        let mask = u32::MAX
            .checked_shl(32 - self.prefix as u32)
            .unwrap_or(u32::MAX);
        (u32::from(self.addr) & mask) == (u32::from(ip) & mask)
    }
}

/// Owns the accounting chain and the previous counter read.
pub struct ClientMonitor {
    dry_run: bool,
    /// Cumulative counters from the previous read, per client.
    prev: HashMap<Ipv4Addr, ClientCounters>,
    /// Clients that currently have rules installed.
    tracked: HashSet<Ipv4Addr>,
    chain_ready: bool,
    /// Whether the counter read at startup actually worked. When it did,
    /// `tracked` is a complete picture of which rules exist and the
    /// existence check before adding one can be skipped — halving the
    /// iptables invocations. When it did not, that check is the only thing
    /// standing between us and a duplicate rule counting everything twice.
    counters_known: bool,
    /// When each stale neighbour was last nudged.
    last_probe: HashMap<Ipv4Addr, Instant>,
    /// Said once rather than every tick.
    warned_capacity: bool,
    warned_unavailable: bool,
}

/// Everything the sampler needs that comes from configuration.
#[derive(Debug, Clone)]
pub struct SampleParams {
    /// Restrict the neighbour scan to this interface when set.
    pub lan_interface: Option<String>,
    /// Never track these — provider gateways, the host's own addresses, and
    /// anything the operator excluded by hand.
    pub excluded: HashSet<Ipv4Addr>,
    /// When non-empty, a client must sit inside one of these networks. On a
    /// single-armed gateway the uplinks share the wire with the LAN, so the
    /// subnets configured on the LAN interface are what separates "a host we
    /// serve" from "somebody else's router".
    pub lan_networks: Vec<Cidr>,
    /// Ceiling on tracked clients, so a rogue LAN cannot grow the ruleset
    /// without bound.
    pub max_tracked: usize,
    /// Refresh stale neighbours with a ping so a quiet host is not reported
    /// as gone.
    pub presence_probe: bool,
}

impl SampleParams {
    /// Is this address one of ours to account for?
    pub fn accepts(&self, ip: Ipv4Addr) -> bool {
        if !is_trackable(ip) || self.excluded.contains(&ip) {
            return false;
        }
        self.lan_networks.is_empty() || self.lan_networks.iter().any(|n| n.contains(ip))
    }
}

/// This host's own IPv4 addresses and the networks they sit on.
///
/// Both are needed: the addresses so the gateway never accounts for itself,
/// the networks so it knows which neighbours are its clients.
pub async fn local_addresses(dev: Option<&str>) -> (HashSet<Ipv4Addr>, Vec<Cidr>) {
    let text = match dev {
        Some(d) => run_stdout("ip", &["-4", "addr", "show", "dev", d]).await,
        None => run_stdout("ip", &["-4", "addr", "show"]).await,
    };
    text.map(|t| parse_local_addrs(&t)).unwrap_or_default()
}

impl ClientMonitor {
    pub fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            prev: HashMap::new(),
            tracked: HashSet::new(),
            chain_ready: false,
            counters_known: false,
            last_probe: HashMap::new(),
            warned_capacity: false,
            warned_unavailable: false,
        }
    }

    /// One sampling round: discover, account, and report per-client deltas.
    ///
    /// The first round after start seeds the baselines and reports every
    /// client with a zero delta. That is deliberate: the counters it reads
    /// may have been accumulating since a previous run of the daemon (the
    /// chain is left in place across restarts, exactly as the routes are), so
    /// attributing all of it to one five-second interval would invent a
    /// gigabyte-per-second spike at every restart.
    pub async fn sample(&mut self, params: &SampleParams) -> Result<Vec<ClientObservation>> {
        if self.dry_run {
            return Ok(Vec::new());
        }
        if !self.chain_ready {
            self.ensure_chain().await?;
            self.chain_ready = true;
            // Adopt whatever the previous run left behind.
            match self.read_counters().await {
                Ok(counters) => {
                    self.tracked = counters.keys().copied().collect();
                    self.prev = counters;
                    self.counters_known = true;
                    if !self.tracked.is_empty() {
                        debug!(
                            clients = self.tracked.len(),
                            "adopted existing per-client accounting rules"
                        );
                    }
                }
                Err(e) => {
                    debug!(error = %e, "could not read existing accounting rules");
                }
            }
        }

        let neighbours = self
            .read_neighbours(params.lan_interface.as_deref())
            .await?;
        let candidates: Vec<&Neighbour> =
            neighbours.iter().filter(|n| params.accepts(n.ip)).collect();

        // Install rules for anything new, within the cap — and only a few
        // per tick. Discovering a whole LAN at once is a burst of serial
        // iptables invocations, each of which takes the xtables lock; on a
        // modest box that burst is long enough to make the daemon look
        // unresponsive to anything asking it a question at the time.
        // Spreading it over a few seconds costs a host nothing and keeps
        // the control socket answering.
        let mut installed_this_tick = 0usize;
        for n in &candidates {
            if self.tracked.contains(&n.ip) {
                continue;
            }
            if installed_this_tick >= MAX_NEW_RULES_PER_TICK {
                debug!(
                    "more new clients than one tick installs rules for; the rest follow \
                     on the next tick"
                );
                break;
            }
            if self.tracked.len() >= params.max_tracked {
                if !self.warned_capacity {
                    self.warned_capacity = true;
                    warn!(
                        max = params.max_tracked,
                        "per-client accounting is at its configured ceiling; further clients \
                         are listed but their traffic is not counted. Raise \
                         clients.max_tracked if this LAN really is this large."
                    );
                }
                break;
            }
            if let Err(e) = self.add_rules(n.ip).await {
                debug!(ip = %n.ip, error = %e, "could not install accounting rules");
                continue;
            }
            self.tracked.insert(n.ip);
            installed_this_tick += 1;
        }

        let counters = self.read_counters().await?;

        // Nudge stale neighbours so a quiet host is not mistaken for a gone
        // one. Fire-and-forget: what matters is the ARP table next tick.
        if params.presence_probe {
            let due: Vec<Ipv4Addr> = candidates
                .iter()
                .filter(|n| n.stale && !n.reachable)
                .map(|n| n.ip)
                .filter(|ip| {
                    self.last_probe
                        .get(ip)
                        .map(|t| t.elapsed() >= PRESENCE_PROBE_EVERY)
                        .unwrap_or(true)
                })
                .take(MAX_PROBES_PER_TICK)
                .collect();
            for ip in &due {
                self.last_probe.insert(*ip, Instant::now());
            }
            probe_presence(&due).await;
        }

        let mut out = Vec::with_capacity(candidates.len());
        for n in candidates {
            let curr = counters.get(&n.ip).copied().unwrap_or_default();
            let delta = match self.prev.get(&n.ip) {
                Some(prev) => ClientCounters::delta(*prev, curr).unwrap_or_default(),
                // Newly tracked: its rules were created this tick, so its
                // counters start at zero and the delta is what they read.
                None => curr,
            };
            self.prev.insert(n.ip, curr);
            out.push(ClientObservation {
                ip: n.ip,
                mac: n.mac.clone(),
                delta,
                seen: n.reachable || !delta.is_zero(),
            });
        }

        // A client that has gone but still has rules keeps its counters, so
        // its history stays readable. Rules are only reclaimed by `forget`.
        Ok(out)
    }

    /// Drop the accounting rules for a client we no longer want to track.
    pub async fn forget(&mut self, ip: Ipv4Addr) {
        if self.dry_run {
            return;
        }
        self.prev.remove(&ip);
        self.last_probe.remove(&ip);
        if !self.tracked.remove(&ip) {
            return;
        }
        for (tag, flag) in [(TAG_DL, "-d"), (TAG_UL, "-s")] {
            let comment = format!("{tag}{ip}");
            let cidr = format!("{ip}/32");
            let _ = run_ok(
                "iptables",
                &[
                    "-t",
                    "filter",
                    "-D",
                    CHAIN,
                    flag,
                    &cidr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                ],
            )
            .await;
        }
        debug!(%ip, "stopped accounting for a client that has been gone a long time");
    }

    async fn ensure_chain(&mut self) -> Result<()> {
        // `-N` fails when the chain already exists, which is the normal case
        // on every run after the first.
        let _ = run_ok("iptables", &["-t", "filter", "-N", CHAIN]).await;

        let hooked = run_ok("iptables", &["-t", "filter", "-C", "FORWARD", "-j", CHAIN])
            .await
            .unwrap_or(false);
        if !hooked {
            let ok = run_ok(
                "iptables",
                &["-t", "filter", "-I", "FORWARD", "1", "-j", CHAIN],
            )
            .await
            .context("failed to invoke iptables to install the accounting chain")?;
            if !ok {
                anyhow::bail!(
                    "could not hook {CHAIN} into FORWARD; per-client traffic cannot be counted"
                );
            }
            info!(
                chain = CHAIN,
                "per-client accounting chain installed in FORWARD"
            );
        }
        Ok(())
    }

    async fn add_rules(&self, ip: Ipv4Addr) -> Result<()> {
        let cidr = format!("{ip}/32");
        for (tag, flag) in [(TAG_DL, "-d"), (TAG_UL, "-s")] {
            let comment = format!("{tag}{ip}");
            let args = [
                "-t",
                "filter",
                "-C",
                CHAIN,
                flag,
                &cidr,
                "-m",
                "comment",
                "--comment",
                &comment,
            ];
            // Skip the existence check when the startup read told us exactly
            // which rules are there: this runs once per client per direction,
            // and on a LAN of any size the saved invocations are the
            // difference between a brief pause and a visible stall. Without
            // that knowledge the check stays — adding a rule that already
            // exists would count every packet twice.
            if !self.counters_known && run_ok("iptables", &args).await.unwrap_or(false) {
                continue;
            }
            let mut add = args;
            add[2] = "-A";
            if !run_ok("iptables", &add)
                .await
                .context("failed to invoke iptables")?
            {
                anyhow::bail!("iptables refused the counting rule for {ip}");
            }
        }
        Ok(())
    }

    /// Read every client's cumulative counters out of the kernel.
    ///
    /// `iptables-save -c` is preferred over the human-readable listing: its
    /// output is a stable, machine-oriented format, whereas `-L -v -x`
    /// right-aligns columns and leaves the target column empty for counting
    /// rules, which is exactly the ambiguity we do not want to parse around.
    async fn read_counters(&mut self) -> Result<HashMap<Ipv4Addr, ClientCounters>> {
        if let Some(text) = run_stdout("iptables-save", &["-c", "-t", "filter"]).await {
            return Ok(parse_iptables_save(&text));
        }
        if let Some(text) =
            run_stdout("iptables", &["-t", "filter", "-L", CHAIN, "-x", "-v", "-n"]).await
        {
            return Ok(parse_iptables_list(&text));
        }
        if !self.warned_unavailable {
            self.warned_unavailable = true;
            warn!(
                "neither `iptables-save` nor `iptables -L` could be read — per-client traffic \
                 will show as zero. Install the iptables package, or set clients.enabled = false."
            );
        }
        Ok(HashMap::new())
    }

    async fn read_neighbours(&self, dev: Option<&str>) -> Result<Vec<Neighbour>> {
        let text = match dev {
            Some(d) => run_stdout("ip", &["-4", "neigh", "show", "dev", d]).await,
            None => run_stdout("ip", &["-4", "neigh", "show"]).await,
        };
        let Some(text) = text else {
            anyhow::bail!("`ip neigh show` could not be read");
        };
        Ok(parse_neighbours(&text))
    }
}

/// Addresses that are never a LAN client: this host's loopback, multicast,
/// broadcast, link-local autoconfiguration, and the unspecified address.
fn is_trackable(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_link_local())
}

/// Ping a handful of hosts to refresh their ARP entries. Results are
/// deliberately ignored — the neighbour table is the actual output.
async fn probe_presence(ips: &[Ipv4Addr]) {
    if ips.is_empty() {
        return;
    }
    let mut set = Vec::with_capacity(ips.len());
    for ip in ips {
        let target = ip.to_string();
        set.push(tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                Command::new("ping")
                    .args(["-c", "1", "-W", "1", "-n", "-q", &target])
                    .kill_on_drop(true)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status(),
            )
            .await;
        }));
    }
    for h in set {
        let _ = h.await;
    }
}

/// Run a command, reporting whether it exited zero. `Err` means it could not
/// be spawned at all, which is a different problem from "it said no".
async fn run_ok(bin: &str, args: &[&str]) -> Result<bool> {
    let status = Command::new(bin)
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .with_context(|| format!("failed to invoke `{bin}`"))?;
    Ok(status.success())
}

/// Run a command and return its stdout, or `None` if it could not run or
/// failed.
async fn run_stdout(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ─────────────────────────────────────────────────────────────────────────
// Parsers. Kept pure so the awkward formats are unit-testable without root,
// iptables, or a LAN.
// ─────────────────────────────────────────────────────────────────────────

/// Parse `ip -4 neigh show`.
///
/// ```text
/// 10.0.0.50 dev eth0 lladdr 02:42:0a:00:00:32 REACHABLE
/// 10.0.0.51 dev eth0 lladdr 02:42:0a:00:00:33 STALE
/// 10.0.0.52 dev eth0  FAILED
/// ```
pub fn parse_neighbours(stdout: &str) -> Vec<Neighbour> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = tokens.first() else {
            continue;
        };
        let Ok(ip) = first.parse::<Ipv4Addr>() else {
            continue;
        };
        let mut mac = None;
        for (i, t) in tokens.iter().enumerate() {
            if *t == "lladdr" {
                mac = tokens.get(i + 1).map(|m| m.to_ascii_lowercase());
            }
        }
        // The state is the last token, and there may be several flags.
        let state = tokens.last().copied().unwrap_or("");
        // PERMANENT and NOARP entries are static: the operator asserted the
        // host is there, so believe them.
        let reachable = matches!(
            state,
            "REACHABLE" | "DELAY" | "PROBE" | "PERMANENT" | "NOARP"
        );
        let stale = state == "STALE";
        if mac.is_none() && !reachable {
            // No hardware address and unconfirmed: an entry the kernel
            // created while failing to resolve. Not a client.
            continue;
        }
        out.push(Neighbour {
            ip,
            mac,
            reachable,
            stale,
        });
    }
    out
}

/// Parse `iptables-save -c -t filter`, picking out our tagged rules.
///
/// ```text
/// [1234:567890] -A VLB_CLIENTS -d 10.0.0.50/32 -m comment --comment "vlb:dl:10.0.0.50"
/// ```
pub fn parse_iptables_save(stdout: &str) -> HashMap<Ipv4Addr, ClientCounters> {
    let mut out: HashMap<Ipv4Addr, ClientCounters> = HashMap::new();
    for line in stdout.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some((counts, rule)) = rest.split_once(']') else {
            continue;
        };
        let Some((pkts, bytes)) = counts.split_once(':') else {
            continue;
        };
        let (Ok(pkts), Ok(bytes)) = (pkts.trim().parse::<u64>(), bytes.trim().parse::<u64>())
        else {
            continue;
        };
        let Some((ip, is_download)) = tagged_ip(rule) else {
            continue;
        };
        let entry = out.entry(ip).or_default();
        if is_download {
            entry.rx_bytes = bytes;
            entry.rx_packets = pkts;
        } else {
            entry.tx_bytes = bytes;
            entry.tx_packets = pkts;
        }
    }
    out
}

/// Parse `iptables -t filter -L VLB_CLIENTS -x -v -n`.
///
/// ```text
/// Chain VLB_CLIENTS (1 references)
///     pkts      bytes target     prot opt in     out     source          destination
///     1234     567890            all  --  *      *       0.0.0.0/0       10.0.0.50   /* vlb:dl:10.0.0.50 */
/// ```
///
/// The fallback for hosts without `iptables-save`. Only the first two columns
/// and the comment are read, so the shifting middle columns do not matter.
pub fn parse_iptables_list(stdout: &str) -> HashMap<Ipv4Addr, ClientCounters> {
    let mut out: HashMap<Ipv4Addr, ClientCounters> = HashMap::new();
    for line in stdout.lines() {
        let mut fields = line.split_whitespace();
        let (Some(pkts), Some(bytes)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(pkts), Ok(bytes)) = (pkts.parse::<u64>(), bytes.parse::<u64>()) else {
            continue;
        };
        let Some((ip, is_download)) = tagged_ip(line) else {
            continue;
        };
        let entry = out.entry(ip).or_default();
        if is_download {
            entry.rx_bytes = bytes;
            entry.rx_packets = pkts;
        } else {
            entry.tx_bytes = bytes;
            entry.tx_packets = pkts;
        }
    }
    out
}

/// Find our comment tag anywhere in a rule line and return the address it
/// names plus whether it is the download direction.
fn tagged_ip(line: &str) -> Option<(Ipv4Addr, bool)> {
    for (tag, is_download) in [(TAG_DL, true), (TAG_UL, false)] {
        if let Some(at) = line.find(tag) {
            let rest = &line[at + tag.len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .unwrap_or(rest.len());
            if let Ok(ip) = rest[..end].parse::<Ipv4Addr>() {
                return Some((ip, is_download));
            }
        }
    }
    None
}

/// Parse `ip -4 addr show` into the host's own addresses and the networks
/// they sit on.
///
/// ```text
///     inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0
/// ```
pub fn parse_local_addrs(stdout: &str) -> (HashSet<Ipv4Addr>, Vec<Cidr>) {
    let mut addrs = HashSet::new();
    let mut nets = Vec::new();
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(pos) = tokens.iter().position(|t| *t == "inet") else {
            continue;
        };
        let Some(cidr) = tokens.get(pos + 1) else {
            continue;
        };
        let (addr, prefix) = match cidr.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().unwrap_or(32)),
            None => (*cidr, 32),
        };
        let Ok(ip) = addr.parse::<Ipv4Addr>() else {
            continue;
        };
        addrs.insert(ip);
        nets.push(Cidr { addr: ip, prefix });
        // The broadcast address of the network is never a client.
        if let Some(bpos) = tokens.iter().position(|t| *t == "brd")
            && let Some(Ok(b)) = tokens.get(bpos + 1).map(|b| b.parse::<Ipv4Addr>())
        {
            addrs.insert(b);
        }
    }
    (addrs, nets)
}

/// Parse a dnsmasq lease file: `<expiry> <mac> <ip> <hostname> <client-id>`.
///
/// The hostname is `*` when the client did not send one.
pub fn parse_dnsmasq_leases(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(ip) = f[2].parse::<Ipv4Addr>() else {
            continue;
        };
        let name = f[3];
        if name != "*" && !name.is_empty() {
            out.insert(ip, name.to_string());
        }
    }
    out
}

/// Parse a Kea DHCPv4 lease CSV. The header names the columns, so the
/// positions are read from it rather than assumed.
pub fn parse_kea_leases(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return out;
    };
    let cols: Vec<&str> = header.split(',').map(|c| c.trim()).collect();
    let (Some(ip_at), Some(name_at)) = (
        cols.iter().position(|c| *c == "address"),
        cols.iter().position(|c| *c == "hostname"),
    ) else {
        return out;
    };
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        let (Some(ip), Some(name)) = (f.get(ip_at), f.get(name_at)) else {
            continue;
        };
        let Ok(ip) = ip.trim().parse::<Ipv4Addr>() else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() {
            out.insert(ip, name.to_string());
        }
    }
    out
}

/// Parse an `/etc/hosts`-shaped file: `<ip> <name> [aliases…]`.
pub fn parse_hosts_file(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut f = line.split_whitespace();
        let (Some(ip), Some(name)) = (f.next(), f.next()) else {
            continue;
        };
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.is_loopback() {
            continue;
        }
        out.insert(ip, name.to_string());
    }
    out
}

/// Take the short form of a hostname: `laptop.lan` → `laptop`.
///
/// A LAN listing is read at a glance, and the domain is the same for every
/// row, so it is noise. Addresses are left alone.
pub fn short_hostname(name: &str) -> String {
    if name.parse::<Ipv4Addr>().is_ok() {
        return name.to_string();
    }
    match name.split_once('.') {
        Some((head, _)) if !head.is_empty() => head.to_string(),
        _ => name.to_string(),
    }
}

/// Resolves a display name for a client, cheapest source first.
///
/// Order matters: an operator's own label beats anything discovered, because
/// it is the one source that says what a machine *is* rather than what it
/// called itself when it asked for an address.
pub struct NameResolver {
    labels_by_mac: HashMap<String, String>,
    labels_by_ip: HashMap<Ipv4Addr, String>,
    lease_files: Vec<String>,
    leases: HashMap<Ipv4Addr, String>,
    hosts: HashMap<Ipv4Addr, String>,
    leases_read_at: Option<Instant>,
    /// Reverse lookups are slow and often fruitless; remember the misses too.
    ptr_cache: HashMap<Ipv4Addr, (Option<String>, Instant)>,
    use_ptr: bool,
}

/// How long a discovered name is trusted before the sources are re-read.
const NAME_REFRESH: Duration = Duration::from_secs(60);
/// How long a reverse-DNS answer — including "there is none" — is cached.
const PTR_TTL: Duration = Duration::from_secs(600);
/// Reverse lookups attempted per tick, so a LAN full of unnamed hosts cannot
/// stall the sampler behind a resolver that is not answering.
const MAX_PTR_PER_TICK: usize = 3;

impl NameResolver {
    pub fn new(
        labels_by_mac: HashMap<String, String>,
        labels_by_ip: HashMap<Ipv4Addr, String>,
        lease_files: Vec<String>,
        use_ptr: bool,
    ) -> Self {
        Self {
            labels_by_mac,
            labels_by_ip,
            lease_files,
            leases: HashMap::new(),
            hosts: HashMap::new(),
            leases_read_at: None,
            ptr_cache: HashMap::new(),
            use_ptr,
        }
    }

    /// The operator's own label for a client, if they set one.
    pub fn label(&self, ip: Ipv4Addr, mac: Option<&str>) -> Option<String> {
        if let Some(l) = self.labels_by_ip.get(&ip) {
            return Some(l.clone());
        }
        let mac = mac?.to_ascii_lowercase();
        self.labels_by_mac.get(&mac).cloned()
    }

    /// Best-effort hostname from DHCP leases, `/etc/hosts` or reverse DNS.
    ///
    /// `budget` caps how many reverse lookups this call may perform, shared
    /// across the clients resolved in one tick.
    pub async fn hostname(&mut self, ip: Ipv4Addr, budget: &mut usize) -> Option<String> {
        self.refresh_files().await;
        if let Some(n) = self.leases.get(&ip).or_else(|| self.hosts.get(&ip)) {
            return Some(short_hostname(n));
        }
        if !self.use_ptr {
            return None;
        }
        if let Some((cached, at)) = self.ptr_cache.get(&ip)
            && at.elapsed() < PTR_TTL
        {
            return cached.clone();
        }
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let found = reverse_lookup(ip).await.map(|n| short_hostname(&n));
        self.ptr_cache.insert(ip, (found.clone(), Instant::now()));
        found
    }

    /// A fresh tick's worth of reverse-lookup budget.
    pub fn ptr_budget(&self) -> usize {
        if self.use_ptr { MAX_PTR_PER_TICK } else { 0 }
    }

    async fn refresh_files(&mut self) {
        if self
            .leases_read_at
            .map(|t| t.elapsed() < NAME_REFRESH)
            .unwrap_or(false)
        {
            return;
        }
        self.leases_read_at = Some(Instant::now());

        let mut leases = HashMap::new();
        for path in &self.lease_files {
            let Ok(text) = tokio::fs::read_to_string(path).await else {
                continue;
            };
            let parsed = if path.ends_with(".csv") {
                parse_kea_leases(&text)
            } else {
                parse_dnsmasq_leases(&text)
            };
            leases.extend(parsed);
        }
        self.leases = leases;

        if let Ok(text) = tokio::fs::read_to_string("/etc/hosts").await {
            self.hosts = parse_hosts_file(&text);
        }
    }
}

/// Reverse-resolve through the system's own configuration.
///
/// `getent hosts` is used rather than a DNS query of our own because it
/// honours `/etc/nsswitch.conf`: on a box where names come from a local
/// resolver, an mDNS responder or a static file, it finds them where a
/// hand-rolled PTR query would not.
async fn reverse_lookup(ip: Ipv4Addr) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new("getent")
            .args(["hosts", &ip.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let name = text.split_whitespace().nth(1)?;
    if name.is_empty() || name.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn neighbours_are_parsed_with_state_and_mac() {
        let out = "10.0.0.50 dev eth0 lladdr 02:42:0a:00:00:32 REACHABLE\n\
                   10.0.0.51 dev eth0 lladdr 02:42:0A:00:00:33 STALE\n\
                   10.0.0.52 dev eth0  FAILED\n\
                   10.0.0.53 dev eth0 lladdr 02:42:0a:00:00:35 PERMANENT\n\
                   fe80::1 dev eth0 lladdr 02:42:0a:00:00:36 REACHABLE\n";
        let n = parse_neighbours(out);
        assert_eq!(n.len(), 3, "{n:?}");

        assert_eq!(n[0].ip, ip("10.0.0.50"));
        assert!(n[0].reachable && !n[0].stale);
        // MAC addresses are normalised so a config label matches whatever
        // case the kernel happens to print.
        assert_eq!(n[1].mac.as_deref(), Some("02:42:0a:00:00:33"));
        assert!(n[1].stale && !n[1].reachable);
        // A static entry counts as confirmed: the operator said so.
        assert!(n[2].reachable);

        // FAILED with no hardware address is an unresolved probe, not a host.
        assert!(!n.iter().any(|x| x.ip == ip("10.0.0.52")));
    }

    #[test]
    fn counters_come_from_iptables_save() {
        let out = "\
# Generated by iptables-save
*filter
:FORWARD ACCEPT [0:0]
:VLB_CLIENTS - [0:0]
[9:1234] -A FORWARD -j VLB_CLIENTS
[10:5000] -A VLB_CLIENTS -d 10.0.0.50/32 -m comment --comment \"vlb:dl:10.0.0.50\"
[4:600] -A VLB_CLIENTS -s 10.0.0.50/32 -m comment --comment \"vlb:ul:10.0.0.50\"
[0:0] -A VLB_CLIENTS -d 10.0.0.51/32 -m comment --comment \"vlb:dl:10.0.0.51\"
COMMIT
";
        let c = parse_iptables_save(out);
        assert_eq!(c.len(), 2);
        let a = c[&ip("10.0.0.50")];
        assert_eq!(a.rx_bytes, 5000);
        assert_eq!(a.rx_packets, 10);
        assert_eq!(a.tx_bytes, 600);
        assert_eq!(a.tx_packets, 4);
        // A client with only one direction recorded still appears, at zero.
        assert_eq!(c[&ip("10.0.0.51")].rx_bytes, 0);
        assert_eq!(c[&ip("10.0.0.51")].tx_bytes, 0);
    }

    /// Some builds print the comment unquoted. Locating the tag by substring
    /// rather than by tokenising the line covers both.
    #[test]
    fn unquoted_comments_parse_too() {
        let out = "[7:99] -A VLB_CLIENTS -s 10.0.0.9/32 -m comment --comment vlb:ul:10.0.0.9\n";
        let c = parse_iptables_save(out);
        assert_eq!(c[&ip("10.0.0.9")].tx_bytes, 99);
    }

    #[test]
    fn counters_fall_back_to_the_listing_format() {
        let out = "Chain VLB_CLIENTS (1 references)\n\
             pkts      bytes target     prot opt in     out     source               destination\n\
               12       3400            all  --  *      *       0.0.0.0/0            10.0.0.50            /* vlb:dl:10.0.0.50 */\n\
                5        700            all  --  *      *       10.0.0.50            0.0.0.0/0            /* vlb:ul:10.0.0.50 */\n";
        let c = parse_iptables_list(out);
        assert_eq!(c[&ip("10.0.0.50")].rx_bytes, 3400);
        assert_eq!(c[&ip("10.0.0.50")].tx_bytes, 700);
    }

    /// The header row of the listing starts with words, not numbers, and the
    /// chain line mentions the chain name — neither may be read as a rule.
    #[test]
    fn listing_headers_are_not_mistaken_for_rules() {
        let out = "Chain VLB_CLIENTS (1 references)\n pkts bytes target prot opt in out source destination\n";
        assert!(parse_iptables_list(out).is_empty());
    }

    #[test]
    fn deltas_skip_a_counter_reset() {
        let a = ClientCounters {
            rx_bytes: 100,
            tx_bytes: 50,
            ..Default::default()
        };
        let b = ClientCounters {
            rx_bytes: 180,
            tx_bytes: 60,
            ..Default::default()
        };
        let d = ClientCounters::delta(a, b).unwrap();
        assert_eq!(d.rx_bytes, 80);
        assert_eq!(d.tx_bytes, 10);
        // Rules re-created: counters restart, and the interval is unknowable.
        assert!(ClientCounters::delta(b, a).is_none());
    }

    #[test]
    fn local_addresses_and_networks_are_extracted() {
        let out = "\
1: lo: <LOOPBACK,UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500
    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0
";
        let (addrs, nets) = parse_local_addrs(out);
        assert!(addrs.contains(&ip("10.0.0.1")));
        // The broadcast address is never a client.
        assert!(addrs.contains(&ip("10.0.0.255")));
        assert!(
            nets.iter()
                .any(|n| n.prefix == 24 && n.contains(ip("10.0.0.50")))
        );
        assert!(
            !nets
                .iter()
                .any(|n| n.prefix == 24 && n.contains(ip("10.1.0.50")))
        );
    }

    #[test]
    fn cidr_membership() {
        let net = Cidr {
            addr: ip("192.168.8.1"),
            prefix: 22,
        };
        assert!(net.contains(ip("192.168.8.7")));
        assert!(net.contains(ip("192.168.11.250")));
        assert!(!net.contains(ip("192.168.12.1")));
        // A /32 contains only itself; a /0 contains everything.
        assert!(
            Cidr {
                addr: ip("1.2.3.4"),
                prefix: 32
            }
            .contains(ip("1.2.3.4"))
        );
        assert!(
            !Cidr {
                addr: ip("1.2.3.4"),
                prefix: 32
            }
            .contains(ip("1.2.3.5"))
        );
        assert!(
            Cidr {
                addr: ip("0.0.0.0"),
                prefix: 0
            }
            .contains(ip("8.8.8.8"))
        );
    }

    /// The filter that decides whether a neighbour is a client of ours.
    /// Getting this wrong in either direction is bad: too loose and the ISP's
    /// own router appears in the operator's list of "users"; too tight and a
    /// real client is invisible.
    #[test]
    fn candidate_filter_excludes_gateways_and_foreign_subnets() {
        let mut excluded = HashSet::new();
        excluded.insert(ip("10.0.0.1")); // us
        excluded.insert(ip("10.0.0.2")); // a provider gateway
        let p = SampleParams {
            lan_interface: Some("eth0".into()),
            excluded,
            lan_networks: vec![Cidr {
                addr: ip("10.0.0.1"),
                prefix: 24,
            }],
            max_tracked: 512,
            presence_probe: true,
        };

        assert!(p.accepts(ip("10.0.0.50")));
        assert!(!p.accepts(ip("10.0.0.1")), "the gateway itself");
        assert!(!p.accepts(ip("10.0.0.2")), "an uplink's next hop");
        assert!(!p.accepts(ip("192.0.2.10")), "outside the LAN");
        assert!(!p.accepts(ip("224.0.0.251")), "multicast");

        // With no networks configured, only the exclusion list applies.
        let open = SampleParams {
            lan_networks: Vec::new(),
            ..p
        };
        assert!(open.accepts(ip("192.0.2.10")));
    }

    #[test]
    fn addresses_that_are_never_clients() {
        assert!(is_trackable(ip("10.0.0.50")));
        assert!(!is_trackable(ip("127.0.0.1")));
        assert!(!is_trackable(ip("224.0.0.1")));
        assert!(!is_trackable(ip("255.255.255.255")));
        assert!(!is_trackable(ip("0.0.0.0")));
        assert!(!is_trackable(ip("169.254.3.4")));
    }

    #[test]
    fn dnsmasq_leases_give_hostnames() {
        let text = "1767225600 02:42:0a:00:00:32 10.0.0.50 denis-pc 01:02:42:0a:00:00:32\n\
                    1767225600 02:42:0a:00:00:33 10.0.0.51 * *\n";
        let l = parse_dnsmasq_leases(text);
        assert_eq!(l.get(&ip("10.0.0.50")).unwrap(), "denis-pc");
        // `*` means the client sent no name — not a client called "*".
        assert!(!l.contains_key(&ip("10.0.0.51")));
    }

    #[test]
    fn kea_leases_are_read_by_column_name() {
        let text = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n\
                    10.0.0.60,02:42:0a:00:00:3c,,3600,1767225600,1,0,0,tablet,0\n";
        let l = parse_kea_leases(text);
        assert_eq!(l.get(&ip("10.0.0.60")).unwrap(), "tablet");
    }

    #[test]
    fn hosts_file_entries_are_read() {
        let text = "127.0.0.1 localhost\n10.0.0.70 printer.lan printer  # the noisy one\n";
        let h = parse_hosts_file(text);
        assert_eq!(h.get(&ip("10.0.0.70")).unwrap(), "printer.lan");
        // Loopback names are not LAN clients.
        assert!(!h.contains_key(&ip("127.0.0.1")));
    }

    #[test]
    fn hostnames_are_shortened_for_the_table() {
        assert_eq!(short_hostname("laptop.lan"), "laptop");
        assert_eq!(short_hostname("laptop"), "laptop");
        assert_eq!(short_hostname("10.0.0.5"), "10.0.0.5");
        assert_eq!(short_hostname(".hidden"), ".hidden");
    }

    #[test]
    fn operator_labels_win_and_are_case_insensitive() {
        let mut by_mac = HashMap::new();
        by_mac.insert("aa:bb:cc:dd:ee:ff".to_string(), "Denis PC".to_string());
        let mut by_ip = HashMap::new();
        by_ip.insert(ip("10.0.0.9"), "NAS".to_string());
        let r = NameResolver::new(by_mac, by_ip, Vec::new(), false);

        assert_eq!(
            r.label(ip("10.0.0.50"), Some("AA:BB:CC:DD:EE:FF"))
                .as_deref(),
            Some("Denis PC")
        );
        assert_eq!(r.label(ip("10.0.0.9"), None).as_deref(), Some("NAS"));
        assert_eq!(r.label(ip("10.0.0.51"), Some("00:00:00:00:00:01")), None);
    }
}
