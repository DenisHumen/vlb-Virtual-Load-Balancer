//! btop-style host metrics sampler.
//!
//! Collects the same set of signals btop / htop display: per-core CPU
//! utilisation, total/used memory, swap, load average, disk totals and
//! aggregate network I/O. The sampler is deliberately cheap — it uses a
//! single `sysinfo::System` instance refreshed on every tick, not a new
//! allocation each call.
//!
//! The heavy `sysinfo::System` state (`Arc<Mutex<…>>`) is owned by the
//! background loop in `balancer::system_loop`; this module only offers the
//! value types and a stateless `sample()` helper for tests.

use serde::{Deserialize, Serialize};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

/// Flattened system snapshot that goes to the DB, the control port and
/// the TUI. All numeric fields are intentionally plain primitives so the
/// struct serialises cleanly to JSON and SQLite.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysSample {
    /// Aggregate CPU usage in the range [0, 100].
    pub cpu_total: f32,
    /// Per-core usage (percent) — same ordering as `/proc/stat`.
    pub cpu_per_core: Vec<f32>,

    /// Memory in bytes.
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_available: u64,

    /// Swap in bytes.
    pub swap_total: u64,
    pub swap_used: u64,

    /// Kernel load averages (1 / 5 / 15 minutes).
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,

    /// Host-wide network aggregate in bytes since the last sample. Distinct
    /// from per-provider traffic because this covers *every* interface and
    /// catches e.g. IPsec tunnels, docker bridges, or traffic on the LAN
    /// interface that is not attributed to any provider.
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,

    /// Root filesystem bytes. Optional because on some containers with no
    /// mount we cannot identify which disk is `/`.
    pub disk_total: u64,
    pub disk_used: u64,

    /// System uptime in seconds. Handy in the TUI header.
    pub uptime_s: u64,
    /// Number of processes in the procfs at sample time.
    pub procs: u64,
}

impl SysSample {
    pub fn mem_pct(&self) -> f32 {
        if self.mem_total == 0 {
            0.0
        } else {
            (self.mem_used as f64 / self.mem_total as f64 * 100.0) as f32
        }
    }

    pub fn swap_pct(&self) -> f32 {
        if self.swap_total == 0 {
            0.0
        } else {
            (self.swap_used as f64 / self.swap_total as f64 * 100.0) as f32
        }
    }

    pub fn disk_pct(&self) -> f32 {
        if self.disk_total == 0 {
            0.0
        } else {
            (self.disk_used as f64 / self.disk_total as f64 * 100.0) as f32
        }
    }
}

/// Owning wrapper around [`sysinfo::System`] so call-sites don't pull in
/// the `sysinfo` namespace and we can centralise the `refresh_*` choices.
///
/// Two refreshes are required for an accurate CPU reading: the crate
/// documents that CPU % is computed between two consecutive refreshes.
/// `balancer::system_loop` therefore calls `sample()` once per tick and
/// discards the first value (the initial `new_with_specifics` refresh
/// seeds the baseline).
pub struct SysMonitor {
    sys: System,
    prev_net_rx: u64,
    prev_net_tx: u64,
    net_initialised: bool,
}

impl SysMonitor {
    pub fn new() -> Self {
        let spec = RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything())
            .with_processes(ProcessRefreshKind::new());
        let sys = System::new_with_specifics(spec);
        Self {
            sys,
            prev_net_rx: 0,
            prev_net_tx: 0,
            net_initialised: false,
        }
    }

    /// Refresh and emit one sample. The `network` delta is computed against
    /// the previous call; the first call therefore always reports
    /// `net_rx_bytes = 0` / `net_tx_bytes = 0`, which is intentional.
    pub fn sample(&mut self) -> SysSample {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        // Refresh process list so `procs` reflects reality. We use a
        // minimal ProcessRefreshKind because we only need the count.
        self.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, ProcessRefreshKind::new());

        // Compute host-wide network aggregate by summing every interface
        // reported by sysinfo. `Networks::new_with_refreshed_list` is used
        // only to obtain a fresh snapshot each tick; accumulating into a
        // u64 is always safe here because sysinfo exposes totals.
        let nets = sysinfo::Networks::new_with_refreshed_list();
        let mut total_rx: u64 = 0;
        let mut total_tx: u64 = 0;
        for (_name, data) in nets.iter() {
            total_rx = total_rx.saturating_add(data.total_received());
            total_tx = total_tx.saturating_add(data.total_transmitted());
        }

        let (dx_rx, dx_tx) = if self.net_initialised {
            (
                total_rx.saturating_sub(self.prev_net_rx),
                total_tx.saturating_sub(self.prev_net_tx),
            )
        } else {
            (0, 0)
        };
        self.prev_net_rx = total_rx;
        self.prev_net_tx = total_tx;
        self.net_initialised = true;

        // Disk total: aggregate every mounted disk. We don't try to pick a
        // "/" mount because it is not portable across container layouts;
        // summing all fixed disks gives a meaningful "total storage" number
        // that btop also uses in its overview mode.
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let mut disk_total: u64 = 0;
        let mut disk_used: u64 = 0;
        for d in disks.iter() {
            let total = d.total_space();
            let avail = d.available_space();
            disk_total = disk_total.saturating_add(total);
            disk_used = disk_used.saturating_add(total.saturating_sub(avail));
        }

        let load = System::load_average();
        let cpus = self.sys.cpus();
        let cpu_per_core: Vec<f32> = cpus.iter().map(|c| c.cpu_usage()).collect();
        let cpu_total = if cpu_per_core.is_empty() {
            0.0
        } else {
            cpu_per_core.iter().sum::<f32>() / cpu_per_core.len() as f32
        };

        SysSample {
            cpu_total,
            cpu_per_core,
            mem_total: self.sys.total_memory(),
            mem_used: self.sys.used_memory(),
            mem_available: self.sys.available_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
            load1: load.one,
            load5: load.five,
            load15: load.fifteen,
            net_rx_bytes: dx_rx,
            net_tx_bytes: dx_tx,
            disk_total,
            disk_used,
            uptime_s: System::uptime(),
            procs: self.sys.processes().len() as u64,
        }
    }
}

impl Default for SysMonitor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_produces_sane_values() {
        let mut m = SysMonitor::new();
        // First sample seeds network baseline; second one has real deltas.
        let _ = m.sample();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let s = m.sample();
        assert!(s.mem_total > 0, "total memory must be > 0 on any running host");
        assert!(s.cpu_total >= 0.0 && s.cpu_total <= 100.0 * s.cpu_per_core.len() as f32);
        assert!(s.mem_pct() >= 0.0 && s.mem_pct() <= 100.0);
        // load average is always available on Linux/macOS; on Windows
        // sysinfo returns zeros which still satisfies the bound.
        assert!(s.load1 >= 0.0);
    }

    #[test]
    fn percentage_helpers_zero_total_safe() {
        let s = SysSample::default();
        assert_eq!(s.mem_pct(), 0.0);
        assert_eq!(s.swap_pct(), 0.0);
        assert_eq!(s.disk_pct(), 0.0);
    }
}
