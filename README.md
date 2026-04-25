# vlb — Virtual Load Balancer

[![CI](https://github.com/denishumen/vlb/actions/workflows/ci.yml/badge.svg)](https://github.com/denishumen/vlb/actions)
[![Release](https://github.com/denishumen/vlb/actions/workflows/release.yml/badge.svg)](https://github.com/denishumen/vlb/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/Rust-1.88%2B-blue.svg)](https://www.rust-lang.org)

Multi-uplink failover gateway for Linux. Turns one box into an active/standby
router across several upstream ISPs: probes every provider independently,
installs the highest-priority healthy one as the kernel default route,
flushes conntrack on switch, and ships a TUI / control protocol / SQLite
stats so you can actually see what's happening.

> **Status:** alpha (`0.0.1-alpha`). Tested in production-like environments,
> but breaking changes can still happen between alpha tags.

---

## Why

If you have two or more ISPs hooked up to one Linux box, the usual options
are:

* **Multi-WAN routers** — black box, often Lua/UI-only, hard to integrate.
* **Bash + cron + ping** — fine until the day a provider answers ICMP for
  `1.1.1.1` but black-holes everything else.
* **`mwan3` / `keepalived` / OSPF** — overkill for a "one gateway, two
  uplinks" home/office setup, and weak for the failure modes that actually
  bite (DNS-only outages, intermittent ICMP-prohibited, partial blocking).

`vlb` is the in-between: a single binary that probes properly, switches
fast, and gives you a real dashboard.

---

## What it actually does

* **Per-provider, fwmark-bound probes**, all independent of which provider
  currently owns the default route. Each provider gets its own routing
  table (`ip rule fwmark`) so we can verify any uplink any time.
* **Three layers of health checks** per provider:
  1. **Gateway**: ICMP to next-hop on the LAN.
  2. **Internet**: 3-packet ICMP burst (≥2 replies needed) to a list of
     external targets — IPs *and hostnames*. Hostnames are resolved
     through that provider's DNS, so the resolved IP is reachable via the
     same uplink.
  3. **DNS**: explicit UDP/53 round-trip to public resolvers, again
     fwmarked. Catches "ICMP works but DNS is blocked" outages typical of
     unpaid-account / captive-portal upstreams.
* **Selectively-prohibited detection**: if any hostname target is
  configured, at least one of them must succeed — so a happy `1.1.1.1`
  reply can't mask an uplink that returns
  `Destination Net Prohibited` for everything else.
* **Deterministic priority-based selection** with separate fail / recover
  thresholds (anti-flap).
* **Default route written as `metric 0 proto static`** so it cleanly
  replaces existing netplan / DHCP defaults instead of coexisting with
  them — failback to the primary actually works.
* **Conntrack flush on every switchover** so live flows reset
  immediately instead of black-holing until TCP timeout.
* **Force / auto control** via TCP control socket (and TUI hotkey `f`):
  pin a specific provider as long as you like; pin survives even when
  the pinned provider is briefly Down (we serve the best healthy one
  meanwhile and snap back when the pin recovers).
* **SQLite stats** (WAL, indexed) for health checks, traffic, host
  metrics, state changes and failover events. 72 h retention by default.
* **TUI dashboard** (ratatui) — provider table, sparklines, traffic and
  CPU/mem graphs, hotkeys for force / auto.
* **Dry-run** that validates and prints every system call without doing
  it. Use this before pointing it at production.
* **Hardened config validator** — rejects reserved tables (253/254/255),
  overlong interface names, fwmark of 0, timeouts >= interval, control
  ports listening on non-loopback, and a few dozen more footguns.

---

## Quick start (development host)

```bash
# 1. clone, build
git clone https://github.com/denishumen/vlb.git
cd vlb
./scripts/vlb.sh build         # bootstraps rustup if needed

# 2. copy and edit the config
cp examples/vlb.example.toml vlb.toml
$EDITOR vlb.toml

# 3. validate it
./scripts/vlb.sh check

# 4. dry-run the daemon (no system mutation)
sudo VLB_CONFIG=$PWD/vlb.toml ./scripts/vlb.sh run --dry-run   # Ctrl+C to stop

# 5. real run, daemonised
sudo VLB_CONFIG=$PWD/vlb.toml ./scripts/vlb.sh start
sudo VLB_CONFIG=$PWD/vlb.toml ./scripts/vlb.sh tui    # dashboard
sudo VLB_CONFIG=$PWD/vlb.toml ./scripts/vlb.sh logs   # tail logs
sudo VLB_CONFIG=$PWD/vlb.toml ./scripts/vlb.sh stop
```

The launcher is documented inline (`./scripts/vlb.sh help`).

---

## Production install (systemd)

```bash
sudo ./scripts/vlb.sh install-service
# → installs /usr/local/bin/vlb,
#   /etc/systemd/system/vlb.service,
#   /etc/vlb/vlb.toml (your current config),
#   enables and starts the unit.

# Operate via systemd
sudo systemctl status vlb
sudo journalctl -u vlb -f
sudo systemctl restart vlb

# Or talk to the running daemon directly
vlb --config /etc/vlb/vlb.toml status
vlb --config /etc/vlb/vlb.toml tui
vlb --config /etc/vlb/vlb.toml stats --hours 24
```

Uninstall with `sudo ./scripts/vlb.sh uninstall-service` (keeps
`/etc/vlb` and the stats DB intact).

---

## Docker / Docker Compose

The container needs `--network host` and `--cap-add NET_ADMIN` (the
daemon manages routes, ip rules, iptables and policy routing — none of
that works in a default container netns).

```bash
# Build and start (compose file lives in ./docker)
docker compose -f docker/docker-compose.yml up -d --build

# Tail
docker compose -f docker/docker-compose.yml logs -f

# TUI inside the container
docker compose -f docker/docker-compose.yml exec vlb \
    vlb --config /etc/vlb/vlb.toml tui

# Stop
docker compose -f docker/docker-compose.yml down
```

`docker/docker-compose.yml` mounts `./vlb.toml` read-only and persists the
stats DB under `./data/`. See [`docker/Dockerfile`](docker/Dockerfile) and
[`docker/docker-compose.yml`](docker/docker-compose.yml) for the full picture.

A pre-built image will be published to Docker Hub later; for now the
compose file builds locally.

---

## Configuration reference

Full annotated example: [`examples/vlb.example.toml`](examples/vlb.example.toml). Most
deployments only edit `[general]` and `[[providers]]`.

```toml
[general]
lan_interface   = "ens18"        # interface that fronts your LAN clients
gateway_address = "10.0.0.100"   # this box's own LAN IP

[health]
interval_secs       = 3
timeout_ms          = 1000
failure_threshold   = 2          # ticks down before declaring DOWN
success_threshold   = 2          # ticks up before declaring UP
probe_targets       = ["1.1.1.1", "8.8.8.8", "google.com"]
dns_check_enabled   = true
dns_resolvers       = ["1.1.1.1", "8.8.8.8"]
dns_check_name      = "cloudflare.com"

[routing]
table_base  = 200                # provider tables: 200, 201, ...
fwmark_base = 0x200              # provider marks:  0x200, 0x201, ...
rule_pref   = 32000              # ip rule preference

[firewall]
manage                 = true    # write iptables MASQUERADE / mangle rules
disable_host_firewall  = false   # leave UFW etc. alone

[database]
path = "/var/lib/vlb/stats.db"

[control]
listen = "127.0.0.1:7650"        # control socket; loopback only

[traffic]
enabled         = true
interval_secs   = 2
retention_hours = 72

[system]
enabled         = true
interval_secs   = 2
retention_hours = 72
per_core        = true

[[providers]]
name      = "isp-main"
gateway   = "10.0.0.2"
interface = "ens18"
priority  = 0                    # lower wins
role      = "primary"

[[providers]]
name      = "isp-backup-a"
gateway   = "10.0.0.1"
interface = "ens18"
priority  = 1
role      = "backup"
```

### Probe target rules

* IPv4 literal (e.g. `1.1.1.1`) → ping it directly through the
  provider's mark.
* Anything else → treated as a hostname, resolved via that provider's
  DNS resolvers (also marked), then ping the resolved IP through the
  same mark.
* Mix both. If at least one hostname is configured, at least one
  hostname must pass — so `google.com` failing while `1.1.1.1` works
  still counts as a broken uplink.

---

## CLI

```
vlb run    [--config <path>] [--dry-run]    # foreground daemon
vlb check  [--config <path>]                # validate + summary
vlb status [--config <path>]                # query running daemon
vlb tui    [--config <path>]                # dashboard
vlb force  [--config <path>] <name>         # pin provider
vlb auto   [--config <path>]                # release pin
vlb stats  [--config <path>] [--hours N] [--recent N]
vlb system [--config <path>] [--recent N]
vlb diag   [--config <path>]                # interfaces, DB, ports
```

---

## TUI hotkeys

| Key     | Action                                    |
|---------|-------------------------------------------|
| `↑`/`↓` | Move selection                            |
| `f`     | Force the selected provider               |
| `a`     | Release force, return to auto             |
| `r`     | Force redraw                              |
| `q`     | Quit                                      |

---

## How it works (one paragraph)

For each provider we install one routing table (`ip route add default via
<gw> dev <if> table <N>`), one fwmark policy rule (`ip rule add fwmark
<M> lookup <N>`), and one MASQUERADE rule on egress. Health probes set
`SO_MARK` (DNS) or pass `-m <mark>` (ping), so they always exit through
the chosen provider regardless of the active default. The state machine
counts consecutive successes/failures, picks the lowest-priority healthy
provider as active, and writes the result via `ip route replace default
via <chosen> metric 0 proto static`. On every change we `conntrack -F`
so live flows reset and reconnect.

---

## Failure modes we cover

| Symptom                                              | Detected by                |
|------------------------------------------------------|----------------------------|
| ISP cable / next-hop dead                            | gateway probe              |
| Uplink up, packet loss to internet                   | ICMP burst (≥2 of 3)       |
| Selectively allowed: `1.1.1.1` OK, `google.com` fails | hostname probe is mandatory |
| ICMP works, UDP/53 blocked (unpaid account, portal)  | dedicated DNS probe        |
| Intermittent `Destination Net Prohibited` flapping   | 3-packet burst, errors don't count as `received` |
| Sysctl `ip_forward=0`                                 | startup check (when `firewall.manage = true`) |
| Stale conntrack after switch                          | `conntrack -F` on every change |
| Two coexisting default routes (DHCP + ours)           | `metric 0 proto static` replace |

---

## Building from source

```bash
cargo build --release
# binary at target/release/vlb

# tests (no system mutation)
cargo test --release

# lint clean
cargo clippy --release --all-targets -- -D warnings
```

MSRV is **1.88**. The launcher script (`scripts/vlb.sh`) bootstraps
`rustup` automatically on hosts without a recent toolchain.

---

## Runtime requirements

* Linux kernel with policy routing (`ip rule`, fwmark) — every kernel
  shipped this decade.
* `iproute2` (`ip` command) and `iputils` ping (must support `-m
  <mark>` and fractional `-W`).
* `iptables` NAT table — nftables hosts ship `iptables-nft`, which
  works.
* `conntrack` — optional. Without it the per-failover flush is a
  no-op and flows wait for TCP timeout.
* Root (`CAP_NET_ADMIN` plus write access to `/proc/sys`).

---

## Troubleshooting

**Port already in use on start.**  
Another `vlb` is alive (systemd unit, leftover daemon, etc). Stop it
with `sudo systemctl stop vlb` or `sudo pkill -x vlb` and try again.
The launcher refuses to fork a second daemon on top of an existing one
on purpose.

**`ip route replace … failed`.**  
Usually means another process owns a default at the same `(metric,
proto)` key. We write at `metric 0 proto static` exactly because that
deterministically replaces netplan/networkd defaults. If you still see
it: `ip route show default` should give you the conflicting line.

**Failback never happens after the primary recovers.**  
You probably saw this on a netplan/networkd box. Confirm with `ip route
show default` that the live default is `proto static`, not `proto boot`
or `proto dhcp`. The fix is already in `vlb` (we always write `proto
static`); if you've manually pinned `proto boot` somewhere, remove that.

**Probes pass but the internet is dead.**  
You're hitting selective prohibition. Add a hostname to
`probe_targets` (e.g. `"google.com"`) — IP-only probes can be deceived
by upstreams that allow popular DNS IPs but block everything else.

**`ping: invalid argument: '0x200'`.**  
`iputils-ping`'s `-m` takes decimal. Inside the daemon we always pass
decimal; if you're running ping by hand for diagnostics, do
`-m $((0x200))`.

**`SO_MARK` setsockopt fails with EPERM.**  
You're not root or the binary lost `CAP_NET_ADMIN`. The systemd unit
runs as root. If you're running by hand, prefix with `sudo`.

**Stats DB locked.**  
`*.db-wal` next to `stats.db` plus a stale process. Make sure only one
`vlb` is running.

---

## Repo layout

```
.
├── Cargo.toml
├── README.md
├── LICENSE
├── rustfmt.toml
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── examples/
│   └── vlb.example.toml      # annotated reference config
├── scripts/
│   ├── vlb.sh                # unified launcher (build / start / tui / logs / install-service / …)
│   └── vlb.ps1               # Windows helper (limited; Linux only feature set)
├── systemd/
│   └── vlb.service
└── src/
    ├── main.rs               # CLI dispatch + module wiring
    ├── core/
    │   ├── balancer.rs       # state machine, scheduling, control-plane glue
    │   └── config.rs         # TOML schema + validator
    ├── net/
    │   ├── health.rs         # ICMP / DNS probes (fwmark-bound)
    │   ├── router.rs         # writes to the kernel routing table
    │   ├── system.rs         # iptables / sysctl / ip rule / table bring-up
    │   └── traffic.rs        # /proc/net/dev sampling
    ├── obs/
    │   ├── logger.rs         # tracing setup
    │   ├── stats.rs          # SQLite schema, queries, retention
    │   └── sysmon.rs         # host metric sampling
    └── ui/
        ├── control.rs        # tiny line-delimited JSON control protocol
        └── tui.rs            # dashboard
```

---

## Contributing

PRs welcome. Please run `cargo fmt`, `cargo clippy --release --all-targets
-- -D warnings`, and `cargo test --release` before opening one.

---

## License

MIT — see [`LICENSE`](LICENSE).
