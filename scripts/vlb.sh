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
#   build              Release build (cargo build --release)
#   check              Validate configuration (no side effects)
#   run                Run the balancer in the foreground (needs root on Linux)
#   start              Build + daemonise in background, record PID
#   stop               Stop the background daemon started by `start`
#   restart            stop && start
#   status             Query the running daemon over its control socket
#   tui                Attach the btop-style interactive dashboard
#   stats              Print a stats report (default: last 1h)
#   system             Fetch recent host metric samples (JSON)
#   logs               Tail the daemon log file
#   install-service    Install + enable systemd/vlb.service (Linux, root)
#   uninstall-service  Disable + remove the installed systemd unit
#   help               Show this help
#
# Environment:
#   VLB_CONFIG   path to the TOML config (default: vlb.example.toml)
#   VLB_BIN      path to the vlb binary   (default: ./target/release/vlb)
#   VLB_LOG      path to the log file     (default: /var/log/vlb.log or /tmp/vlb.log)
#   VLB_PID      path to the pid file     (default: /run/vlb.pid or /tmp/vlb.pid)

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
cd "${REPO_DIR}"

VLB_CONFIG=${VLB_CONFIG:-"${REPO_DIR}/vlb.example.toml"}
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
require_bin()   { [[ -x "$VLB_BIN" ]] || { log "building release binary..."; cmd_build; }; }
require_cfg()   { [[ -r "$VLB_CONFIG" ]] || die "config not readable: $VLB_CONFIG"; }

is_running() {
    [[ -f "$VLB_PID" ]] || return 1
    local pid; pid=$(cat "$VLB_PID" 2>/dev/null || true)
    [[ -n "$pid" ]] || return 1
    kill -0 "$pid" 2>/dev/null
}

cmd_build() {
    require_cargo
    log "cargo build --release"
    cargo build --release
    ok "built: $VLB_BIN"
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
    "$VLB_BIN" --config "$VLB_CONFIG" check
    log "starting daemon, log=$VLB_LOG pid=$VLB_PID"
    # nohup + setsid so the daemon survives the script exit and is its own
    # session leader. stdout/stderr → log file.
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

main() {
    local cmd=${1:-help}; shift || true
    case "$cmd" in
        build)              cmd_build ;;
        check)              cmd_check ;;
        run)                cmd_run ;;
        start)              cmd_start ;;
        stop)               cmd_stop ;;
        restart)            cmd_restart ;;
        status)             cmd_status ;;
        tui)                cmd_tui ;;
        stats)              cmd_stats "$@" ;;
        system)             cmd_system "$@" ;;
        logs)               cmd_logs ;;
        install-service)    cmd_install_service ;;
        uninstall-service)  cmd_uninstall_service ;;
        -h|--help|help)     cmd_help ;;
        *) die "unknown command: $cmd (try: $0 help)" ;;
    esac
}

main "$@"
