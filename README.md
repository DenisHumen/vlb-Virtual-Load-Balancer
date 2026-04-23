# Virtual Load Balancer (`vlb`)

High-performance multi-provider failover gateway for Linux. The service turns
one Linux host into an active/standby router across several upstream ISPs: it
continuously probes every provider independently (next-hop reachability **and**
end-to-end internet reachability via a per-provider routing table with
`fwmark`), and installs the highest-priority healthy one as the kernel default
route. Packet forwarding itself stays in the kernel — userspace only decides
*which* next-hop wins.

## Features

- **Independent per-provider health probes** — each provider is verified
  through its own routing table + `ip rule fwmark` entry, so a dead uplink on
  a backup is detected even while the primary is carrying all traffic.
- **Deterministic priority-based selection** with configurable fail/recover
  thresholds to suppress flapping.
- **Conntrack flush on failover** so existing flows fail fast and re-establish
  through the new provider instead of black-holing until TCP timeout.
- **SQLite stats database** (WAL, indexed) with health samples, state
  transitions and failover events — queryable via `vlb stats`.
- **Clean shutdown** on `SIGINT` / `SIGTERM`, coordinated via a `watch`
  channel so every task stops at the next tick.
- **Dry-run mode** that parses, validates, and simulates every system
  modification without touching sysctl / iptables / ip routes.
- **Hardened configuration validator**: rejects reserved routing tables
  (253/254/255), overlong interface names, timeouts ≥ interval, rule prefs
  that would collide with the main table, etc.

## Binary layout

```
vlb run    [--config <path>] [--dry-run]   # default; start the gateway
vlb check  [--config <path>]               # parse + validate + print summary
vlb stats  [--config <path>] [--hours N] [--recent N]
```

## Build

```
cargo build --release
install -m 0755 target/release/vlb /usr/local/bin/vlb
install -D -m 0644 systemd/vlb.service /etc/systemd/system/vlb.service
install -D -m 0644 vlb.example.toml /etc/vlb/vlb.toml   # then edit
systemctl daemon-reload && systemctl enable --now vlb
```

See `vlb.example.toml` for a commented reference configuration.

## Runtime requirements

- Linux kernel with policy routing (`ip rule`, `fwmark`) — standard since
  forever.
- `iproute2` (`ip` command) and `iputils` ping (supports `-m <mark>` and
  fractional `-W`).
- `iptables` (NAT table) — nftables hosts typically ship an `iptables-nft`
  shim; both work.
- `conntrack` is optional — if absent, the per-failover conntrack flush is a
  no-op and flows wait for TCP timeouts instead.
- Root, for `CAP_NET_ADMIN` + write access to `/proc/sys`.

## Tests

```
cargo test                  # unit tests — no system mutation
cargo clippy --all-targets -- -D warnings
```

## License

MIT.
