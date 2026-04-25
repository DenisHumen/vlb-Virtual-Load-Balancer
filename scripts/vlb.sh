#!/usr/bin/env bash
# vlb — unified launcher for the Virtual Load Balancer service.
#
# Handles: build, config check, foreground/daemonised run, TUI, stats, stop,
# status, log tailing, and systemd unit install. Idempotent where possible.
#
# Usage:
#   scripts/vlb.sh <command> [args...]
#
# Commands:
#   (no args)          Alias of `up`: build (if needed) + start daemon + show status
#   up                 Same as above — the one-shot "just start it" entry point
#   build              Release build (cargo build --release)
#   rebuild            Delete binary, rebuild from scratch, restart if running
#   check              Validate configuration (no side effects)
#   run                Run the balancer in the foreground (needs root on Linux)
#   start              Build + daemonise in background, record PID
#   stop               Stop the background daemon started by `start`
#   restart            stop && start
#   status             Query the running daemon over its control socket
#   tui                Attach the btop-style interactive dashboard
#   stats              Print a stats report (default: last 1h)
#   system             Fetch recent host metric samples (JSON)
#   diag               Diagnostic dump (interfaces, DB rows, control port)
#   logs               Tail the daemon log file
#   install-service    Install + enable systemd/vlb.service (Linux, root)
#   uninstall-service  Disable + remove the installed systemd unit
#   help               Show this help
#
# Environment:
#   VLB_CONFIG   path to the TOML config (default: examples/vlb.example.toml)
#   VLB_BIN      path to the vlb binary   (default: ./target/release/vlb)
#   VLB_LOG      path to the log file     (default: /var/log/vlb.log or /tmp/vlb.log)
#   VLB_PID      path to the pid file     (default: /run/vlb.pid or /tmp/vlb.pid)

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
cd "${REPO_DIR}"

VLB_CONFIG=${VLB_CONFIG:-"${REPO_DIR}/examples/vlb.example.toml"}
VLB_BIN=${VLB_BIN:-"${REPO_DIR}/target/release/vlb"}

# Choose writable locations based on effective UID so the script is usable
# both as an operator smoke-test and as a production launcher.
if [[ $EUID -eq 0 ]]; then
    VLB_PID=${VLB_PID:-/run/vlb.pid}
    VLB_LOG=${VLB_LOG:-/var/log/vlb.log}
else
    VLB_PID=${VLB_PID:-/tmp/vlb.pid}
    VLB_LOG=${VLB_LOG:-/tmp/vlb.log}
fi

C_RED='\033[0;31m'; C_GRN='\033[0;32m'; C_YLW='\033[0;33m'; C_CYN='\033[0;36m'; C_RST='\033[0m'
if [[ ! -t 1 ]]; then C_RED=; C_GRN=; C_YLW=; C_CYN=; C_RST=; fi

log()  { printf '%b[vlb]%b %s\n' "$C_CYN" "$C_RST" "$*"; }
ok()   { printf '%b[ ok]%b %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%b[!! ]%b %s\n' "$C_YLW" "$C_RST" "$*"; }
die()  { printf '%b[err]%b %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

require_cargo() { command -v cargo >/dev/null || die "cargo not found — install Rust toolchain"; }

# Minimum Rust version required to build the project. Must match `rust-version`
# in Cargo.toml. Transitive deps (clap_lex 1.1, anstream 1.0, serde 1.0.228)
# use Cargo `edition2024`, which was stabilised in Rust 1.85.
VLB_MIN_RUST="1.85.0"

# Compare two dotted versions; returns 0 iff $1 >= $2.
version_ge() {
    [[ "$1" == "$2" ]] && return 0
    local older
    older=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
    [[ "$older" == "$2" ]]
}

ensure_rust() {
    if command -v rustc >/dev/null; then
        local cur
        cur=$(rustc --version | awk '{print $2}')
        if version_ge "$cur" "$VLB_MIN_RUST"; then
            return 0
        fi
        warn "rustc $cur found, but $VLB_MIN_RUST+ required"
    else
        warn "rustc not found"
    fi

    if command -v rustup >/dev/null; then
        log "upgrading toolchain via rustup (rustup update stable && rustup default stable)"
        rustup install stable >/dev/null
        rustup default stable >/dev/null
        return 0
    fi

    warn "rustup not installed — bootstrapping from https://sh.rustup.rs"
    if ! command -v curl >/dev/null; then
        die "need curl to bootstrap rustup; install it (or install Rust ≥$VLB_MIN_RUST manually) and rerun"
    fi
    # -y non-interactive, default profile, default stable.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
        --default-toolchain stable --profile minimal
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    command -v cargo >/dev/null || die "rustup install failed — see output above"
    ok "rust toolchain installed: $(rustc --version)"
}

require_bin() {
    # Rebuild when the binary is missing OR when any source file (Cargo.toml,
    # Cargo.lock, anything under src/) is newer than it. Without this, a
    # stale binary from a previous build would silently be used after edits —
    # which is exactly how operators end up debugging "fixed" code.
    local need_build=0
    if [[ ! -x "$VLB_BIN" ]]; then
        need_build=1
    else
        local newer
        newer=$(find "${REPO_DIR}/src" "${REPO_DIR}/Cargo.toml" "${REPO_DIR}/Cargo.lock" \
                     -type f -newer "$VLB_BIN" -print -quit 2>/dev/null || true)
        if [[ -n "$newer" ]]; then
            log "source newer than binary ($newer) — rebuilding"
            need_build=1
        fi
    fi
    if (( need_build )); then
        ensure_rust
        log "building release binary..."
        cmd_build
    fi
}
require_cfg()   { [[ -r "$VLB_CONFIG" ]] || die "config not readable: $VLB_CONFIG"; }

is_running() {
    [[ -f "$VLB_PID" ]] || return 1
    local pid; pid=$(cat "$VLB_PID" 2>/dev/null || true)
    [[ -n "$pid" ]] || return 1
    kill -0 "$pid" 2>/dev/null
}

cmd_build() {
    ensure_rust
    require_cargo
    # --locked forces cargo to honour the shipped Cargo.lock so we don't
    # pull transitive crates that need a newer Rust than our MSRV.
    local lock_flag="--locked"
    [[ -f "${REPO_DIR}/Cargo.lock" ]] || lock_flag=""
    log "cargo build --release ${lock_flag}"
    cargo build --release ${lock_flag}
    ok "built: $VLB_BIN"
}

cmd_rebuild() {
    # Force a fresh build regardless of timestamps, then restart.
    rm -f "$VLB_BIN"
    cmd_build
    if is_running; then
        log "restarting with new binary"
        cmd_stop
        cmd_start
    fi
}

cmd_check() {
    require_bin; require_cfg
    "$VLB_BIN" --config "$VLB_CONFIG" check
}

cmd_run() {
    require_bin; require_cfg
    exec "$VLB_BIN" --config "$VLB_CONFIG" run
}

cmd_start() {
    require_bin; require_cfg
    if is_running; then
        warn "already running (pid $(cat "$VLB_PID"))"
        return 0
    fi
    # Guard against a stale second daemon — systemd unit or a previous run
    # with a different pid file could still be holding the control port.
    local listen port
    listen=$(grep -E '^\s*listen\s*=' "$VLB_CONFIG" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    port=${listen##*:}
    if [[ -n "$port" ]] && command -v ss >/dev/null && ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
        warn "port $port already in use — another vlb instance (maybe systemd) is running"
        warn "stop it first:  sudo systemctl stop vlb  ||  pkill -x vlb"
        die "refusing to start a second daemon"
    fi
    "$VLB_BIN" --config "$VLB_CONFIG" check
    log "starting daemon, log=$VLB_LOG pid=$VLB_PID"
    nohup setsid "$VLB_BIN" --config "$VLB_CONFIG" run \
        >>"$VLB_LOG" 2>&1 &
    echo $! >"$VLB_PID"
    sleep 0.5
    if is_running; then
        ok "started pid=$(cat "$VLB_PID")"
    else
        die "daemon exited immediately — see $VLB_LOG"
    fi
}

cmd_stop() {
    if ! is_running; then
        warn "not running"
        rm -f "$VLB_PID"
        return 0
    fi
    local pid; pid=$(cat "$VLB_PID")
    log "stopping pid=$pid"
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        warn "still alive, sending SIGKILL"
        kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$VLB_PID"
    ok "stopped"
}

cmd_restart() { cmd_stop; cmd_start; }

cmd_status() {
    require_bin; require_cfg
    if is_running; then ok "daemon pid=$(cat "$VLB_PID")"; else warn "daemon not running via $VLB_PID"; fi
    "$VLB_BIN" --config "$VLB_CONFIG" status || true
}

cmd_tui()    { require_bin; require_cfg; exec "$VLB_BIN" --config "$VLB_CONFIG" tui; }
cmd_stats()  { require_bin; require_cfg; "$VLB_BIN" --config "$VLB_CONFIG" stats "$@"; }
cmd_system() { require_bin; require_cfg; "$VLB_BIN" --config "$VLB_CONFIG" system "$@"; }
cmd_diag()   { require_bin; require_cfg; "$VLB_BIN" --config "$VLB_CONFIG" diag; }

cmd_logs() {
    [[ -f "$VLB_LOG" ]] || die "no log file at $VLB_LOG"
    exec tail -F -n 200 "$VLB_LOG"
}

cmd_install_service() {
    [[ $EUID -eq 0 ]] || die "install-service must run as root"
    command -v systemctl >/dev/null || die "systemctl not found — not a systemd host?"
    local unit_src="${REPO_DIR}/systemd/vlb.service"
    [[ -f "$unit_src" ]] || die "missing $unit_src"
    require_bin
    install -m 0755 -D "$VLB_BIN" /usr/local/bin/vlb
    install -m 0644 -D "$unit_src" /etc/systemd/system/vlb.service
    install -m 0644 -D "$VLB_CONFIG" /etc/vlb/vlb.toml
    systemctl daemon-reload
    systemctl enable --now vlb.service
    ok "service installed, enabled and started"
    systemctl --no-pager status vlb.service || true
}

cmd_uninstall_service() {
    [[ $EUID -eq 0 ]] || die "uninstall-service must run as root"
    systemctl disable --now vlb.service 2>/dev/null || true
    rm -f /etc/systemd/system/vlb.service
    systemctl daemon-reload
    ok "service removed (config at /etc/vlb kept intact)"
}

cmd_help() { sed -n '2,30p' "$0"; }

cmd_up() {
    # "just start everything" — build if needed, start daemon, show status.
    require_bin
    require_cfg
    if ! is_running; then cmd_start; fi
    cmd_status || true
    log "done. attach the dashboard with:  $0 tui"
    log "stop the daemon with:            $0 stop"
}

main() {
    # No args → full bring-up (build + start + status). This is the "just run
    # it" path the operator asked for.
    local cmd=${1:-up}; shift || true
    case "$cmd" in
        up)                 cmd_up ;;
        build)              cmd_build ;;
        rebuild)            cmd_rebuild ;;
        check)              cmd_check ;;
        run)                cmd_run ;;
        start)              cmd_start ;;
        stop)               cmd_stop ;;
        restart)            cmd_restart ;;
        status)             cmd_status ;;
        tui)                cmd_tui ;;
        stats)              cmd_stats "$@" ;;
        system)             cmd_system "$@" ;;
        diag)               cmd_diag ;;
        logs)               cmd_logs ;;
        install-service)    cmd_install_service ;;
        uninstall-service)  cmd_uninstall_service ;;
        -h|--help|help)     cmd_help ;;
        *) die "unknown command: $cmd (try: $0 help)" ;;
    esac
}

main "$@"
