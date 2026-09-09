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
#   install            Guided setup, and a menu for a gateway already running
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
#   probe              Time every health layer per provider (sizes your timeouts)
#   clients            Who is behind the gateway: traffic, uptime, drops
#   update             Pull, build, deploy and restart; roll back if it fails
#   test               fmt + clippy + unit tests; `test --lab` adds the docker lab
#   logs               Tail the daemon log file
#   install-service    Install + enable systemd/vlb.service (Linux, root)
#   uninstall-service  Disable + remove the installed systemd unit
#   help               Show this help
#
# Updating:
#   sudo bash scripts/vlb.sh update
#
#   From a git checkout that is what it does: pull, build, check the new
#   binary against this machine's own configuration, deploy it to wherever
#   the service actually runs it from, restart, and wait for it to answer. If
#   it does not come back, the previous binary is put back and the reason is
#   printed. Off a checkout it hands over to the daemon's own release updater,
#   which has the same safety net. Force either with `update --git` or
#   `update --release`.
#
#   The restart does not interrupt traffic: the new daemon adopts the route
#   the old one left in the kernel rather than choosing again.
#
# Environment:
#   VLB_CONFIG   path to the TOML config (default: examples/vlb.example.toml)
#   VLB_BIN      path to the vlb binary   (default: ./target/release/vlb)
#   VLB_LOG      path to the log file     (default: /var/log/vlb.log or /tmp/vlb.log)
#   VLB_PID      path to the pid file     (default: /run/vlb.pid or /tmp/vlb.pid)
#   VLB_SERVICE  systemd unit to restart  (default: vlb)
#   VLB_NO_RESTART=1  rebuild without restarting the running daemon

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
cd "${REPO_DIR}"

# The installed config wins over the shipped example when it exists.
#
# The example is tracked by git: running a gateway straight out of it means
# the next `git pull` either refuses to update or quietly rewrites the live
# configuration. /etc/vlb/vlb.toml is where a real deployment keeps it, and
# picking it up automatically is what makes `git pull` safe again.
if [[ -z "${VLB_CONFIG:-}" ]]; then
    if [[ -r /etc/vlb/vlb.toml ]]; then
        VLB_CONFIG=/etc/vlb/vlb.toml
    else
        VLB_CONFIG="${REPO_DIR}/examples/vlb.example.toml"
    fi
fi
VLB_BIN=${VLB_BIN:-"${REPO_DIR}/target/release/vlb"}
VLB_SERVICE=${VLB_SERVICE:-vlb}

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
# in Cargo.toml. Transitive deps (darling 0.23, instability 0.3.12 pulled by
# ratatui) require 1.88 or newer.
VLB_MIN_RUST="1.88.0"

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

# The path systemd will execute, which is not the path a build writes to.
#
# This is the gap the whole update story fell through: `cargo build` writes
# target/release/vlb, the unit's ExecStart is /usr/local/bin/vlb, and a
# `systemctl restart` in between re-executes the *old* binary while printing
# that it restarted. An install adopted from elsewhere may run it from a third
# place, so ask systemd rather than assuming.
deployed_bin() {
    local from_unit=""
    if command -v systemctl >/dev/null; then
        from_unit=$(systemctl show -p ExecStart --value "$VLB_SERVICE" 2>/dev/null \
                      | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1) || true
        [[ -z "$from_unit" ]] && from_unit=$(systemctl cat "$VLB_SERVICE" 2>/dev/null \
                      | sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' | head -n1) || true
    fi
    [[ -n "$from_unit" ]] && { printf '%s' "$from_unit"; return 0; }
    printf '%s' /usr/local/bin/vlb
}

service_active() {
    command -v systemctl >/dev/null \
        && systemctl is-active --quiet "$VLB_SERVICE" 2>/dev/null
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
        restart_after_rebuild
    fi
}

# A rebuild replaces the binary on disk; the *running* daemon carries on with
# the old one until something restarts it. That is the confusing half of
# updating from a git checkout: `git pull` followed by a command that
# rebuilds looks like it updated everything, while the daemon keeps running
# the previous build and none of the new behaviour appears.
#
# So restart it here. This is safe by design: since 0.3.0 a restart does not
# disturb traffic — the new process adopts the default route the old one left
# in the kernel and re-verifies it before it would move anything, so no route
# changes and no connection is reset.
restart_after_rebuild() {
    [[ "${VLB_NO_RESTART:-0}" == "1" ]] && return 0

    local systemd_active=0 pidfile_active=0
    command -v systemctl >/dev/null \
        && systemctl is-active --quiet "$VLB_SERVICE" 2>/dev/null \
        && systemd_active=1
    is_running && pidfile_active=1

    (( systemd_active || pidfile_active )) || return 0

    if [[ $EUID -ne 0 ]]; then
        warn "the binary was rebuilt, but the running daemon is still the old build"
        warn "  restart it with:  sudo bash scripts/vlb.sh restart"
        return 0
    fi

    if (( systemd_active )); then
        # Copy the build to where the unit will look for it. Restarting
        # without this re-runs the previous binary and reports success.
        local deployed; deployed=$(deployed_bin)
        if [[ "$(readlink -f "$VLB_BIN")" != "$(readlink -f "$deployed")" ]]; then
            install -m 0755 "$VLB_BIN" "$deployed" \
                || { warn "could not write ${deployed}; the service still runs the old build"; return 0; }
            log "deployed the new build to ${deployed}"
        fi
        log "restarting ${VLB_SERVICE} so the new build takes over"
        if systemctl restart "$VLB_SERVICE"; then
            ok "${VLB_SERVICE} restarted — traffic kept flowing (the route is adopted, not re-chosen)"
        else
            warn "could not restart ${VLB_SERVICE}; it is still running the previous build"
        fi
    else
        log "restarting the daemon so the new build takes over"
        cmd_stop
        cmd_start
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
    # systemd owns this box: say so and stop, rather than racing the unit for
    # the control port and starting a second balancer. Two balancers both
    # install default routes and both flush conntrack on their own switchovers.
    if service_active; then
        ok "${VLB_SERVICE} is running under systemd — nothing to start"
        log "  restart it with:  sudo systemctl restart ${VLB_SERVICE}"
        return 0
    fi
    if is_running; then
        warn "already running (pid $(cat "$VLB_PID"))"
        return 0
    fi
    # Guard against a stale second daemon — systemd unit or a previous run
    # with a different pid file could still be holding the control port.
    #
    # `listen` is optional in the config; the daemon defaults to
    # 127.0.0.1:7650 when it is absent. A grep that matches nothing exits 1,
    # and under `set -euo pipefail` that used to abort this whole function —
    # silently, with status 0: no daemon started, nothing printed, nothing to
    # go on. Tolerate the miss and fall back to the same default the daemon
    # uses, so the duplicate check still works.
    local listen port
    listen=$(grep -E '^[[:space:]]*listen[[:space:]]*=' "$VLB_CONFIG" 2>/dev/null \
               | head -n1 | sed -E 's/.*"([^"]+)".*/\1/') || true
    [[ -n "$listen" ]] || listen="127.0.0.1:7650"
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
    if service_active; then
        log "stopping ${VLB_SERVICE} (systemd)"
        systemctl stop "$VLB_SERVICE" && ok "stopped" || warn "systemctl stop failed"
        return 0
    fi
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

cmd_restart() {
    # Under systemd a restart is one operation, not a stop and a start: the
    # unit re-executes the deployed binary, and the new process adopts the
    # route the old one left behind, so traffic is not disturbed.
    if service_active; then
        require_bin
        local deployed; deployed=$(deployed_bin)
        if [[ -x "$VLB_BIN" && "$(readlink -f "$VLB_BIN")" != "$(readlink -f "$deployed")" ]]; then
            install -m 0755 "$VLB_BIN" "$deployed"                 || die "could not write ${deployed} — run this as root"
            log "deployed the current build to ${deployed}"
        fi
        log "restarting ${VLB_SERVICE}"
        systemctl restart "$VLB_SERVICE" || die "systemctl restart ${VLB_SERVICE} failed"
        ok "restarted — the route is adopted, not re-chosen, so traffic kept flowing"
        return 0
    fi
    cmd_stop
    cmd_start
}

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
    # Copying a file onto itself is an error, and it is the normal case once
    # VLB_CONFIG already points at the installed configuration.
    if [[ "$(readlink -f "$VLB_CONFIG" 2>/dev/null)" != "$(readlink -f /etc/vlb/vlb.toml 2>/dev/null)" ]]; then
        install -m 0644 -D "$VLB_CONFIG" /etc/vlb/vlb.toml
    fi
    systemctl daemon-reload
    systemctl enable --now vlb.service
    ok "service installed, enabled and started"
    systemctl --no-pager status vlb.service || true
}

# The guided setup lives in its own script: it is a wizard and a menu, not a
# launcher, and keeping it separate keeps this file readable.
cmd_install() {
    local setup="${SCRIPT_DIR}/vlb-setup.sh"
    [[ -f "$setup" ]] || die "missing $setup"
    exec bash "$setup" "$@"
}

cmd_uninstall_service() {
    [[ $EUID -eq 0 ]] || die "uninstall-service must run as root"
    systemctl disable --now vlb.service 2>/dev/null || true
    rm -f /etc/systemd/system/vlb.service
    systemctl daemon-reload
    ok "service removed (config at /etc/vlb kept intact)"
}

cmd_probe()   { require_bin; require_cfg; "$VLB_BIN" --config "$VLB_CONFIG" probe "$@"; }
cmd_clients() { require_bin; require_cfg; "$VLB_BIN" --config "$VLB_CONFIG" clients "$@"; }

# ─────────────────────────────────────────────────────────────────────────
# Updating, and being able to go back
#
# Two ways to update this gateway, and until now only one of them worked.
#
#   * From a GitHub release: the daemon does it itself. `vlb update` fetches
#     the tarball, verifies it, validates this machine's config with the new
#     binary, probes the canary with it, swaps it in, restarts, and puts the
#     old one back if the service does not come home. That path is sound.
#
#   * From this git checkout, which is how this deployment is actually run.
#     The documented recipe — `git pull && vlb.sh restart` — deployed nothing:
#     a build writes target/release/vlb, the unit runs /usr/local/bin/vlb, and
#     the restart in between re-executed the old binary while reporting
#     success. `update` below is that path done properly, with the same
#     promise the release path makes: if the new build does not come back
#     serving, the previous one is restored and the reason is printed.
# ─────────────────────────────────────────────────────────────────────────

# git, run as whoever owns the checkout.
#
# As root it also has to say the directory is not dubious: git refuses to
# operate on a repository owned by somebody else unless told, and that refusal
# would otherwise read as "the pull failed".
as_owner() {
    local who="$1"; shift
    if [[ "$who" == root ]]; then
        git -c "safe.directory=${REPO_DIR}" -C "$REPO_DIR" "$@"
    else
        sudo -u "$who" git -C "$REPO_DIR" "$@"
    fi
}

# Wait until the daemon answers on its control port. Returns 1 on timeout.
wait_until_serving() {
    local secs="${1:-30}" bin="$2"
    for _ in $(seq 1 "$secs"); do
        if "$bin" --config "$VLB_CONFIG" status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# The version the *running daemon* reports, which is not the version of the
# binary on disk.
running_version() {
    # The `|| true` is load-bearing. Under `pipefail` a daemon that is not
    # listening makes this pipeline fail, and `v=$(running_version …)` with
    # `set -e` in force then ends the script mid-update — silently, right
    # after the binary has been replaced and before anything can be rolled
    # back. Found by the lab, which is the only reason it is not still there.
    local out
    out=$("$1" --config "$VLB_CONFIG" status 2>/dev/null || true)
    printf '%s' "$out" \
        | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
}

# What a binary says it is.
binary_version() {
    local out
    out=$("$1" --version 2>/dev/null || true)
    printf '%s' "$out" | awk '{print $NF}'
}

# Wait until the daemon answering is the one we just deployed.
#
# "Something answers" is not the same question. A restart that silently did
# not happen leaves the previous daemon answering happily, and an update that
# checked only for an answer would call that success — which is exactly what
# it did on a box whose systemd unit was not the thing running vlb.
wait_until_version() {
    local bin="$1" want="$2" secs="${3:-30}"
    for _ in $(seq 1 "$secs"); do
        [[ "$(running_version "$bin")" == "$want" ]] && return 0
        sleep 1
    done
    return 1
}

# Restart however this box actually runs the daemon, and say if it could not.
restart_daemon_now() {
    if service_active; then
        log "restarting ${VLB_SERVICE} (systemd)"
        systemctl restart "$VLB_SERVICE" && return 0
        warn "systemctl restart ${VLB_SERVICE} failed"
        return 1
    fi
    if is_running; then
        log "restarting the daemon from its pid file"
        VLB_NO_RESTART=1 bash "${BASH_SOURCE[0]}" stop >/dev/null 2>&1 || true
        VLB_NO_RESTART=1 bash "${BASH_SOURCE[0]}" start >/dev/null 2>&1 && return 0
        warn "could not start the daemon again"
        return 1
    fi
    # A unit that exists but is not running: start it.
    if command -v systemctl >/dev/null \
        && systemctl list-unit-files "${VLB_SERVICE}.service" >/dev/null 2>&1; then
        log "starting ${VLB_SERVICE}"
        systemctl restart "$VLB_SERVICE" && return 0
    fi
    warn "nothing appears to be running, so there was nothing to restart"
    warn "  start it with:  sudo bash scripts/vlb.sh start"
    return 1
}

# Why did it not come back? Whatever the operator would have had to go and
# look up themselves.
failure_reason() {
    if command -v journalctl >/dev/null && systemctl list-unit-files "${VLB_SERVICE}.service" >/dev/null 2>&1; then
        journalctl -u "$VLB_SERVICE" -n 20 --no-pager 2>/dev/null | tail -n 20
    elif [[ -r "$VLB_LOG" ]]; then
        tail -n 20 "$VLB_LOG"
    else
        echo "(no journal and no ${VLB_LOG} to read)"
    fi
}

cmd_update() {
    require_cfg
    local mode="${1:-auto}"
    [[ "$mode" == --release || "$mode" == --git ]] && shift || mode=auto

    if [[ "$mode" == auto ]]; then
        if [[ -d "${REPO_DIR}/.git" ]]; then mode=--git; else mode=--release; fi
    fi

    if [[ "$mode" == --release ]]; then
        # The daemon's own updater, which already has the full safety net.
        local bin; bin=$(deployed_bin)
        [[ -x "$bin" ]] || bin="$VLB_BIN"
        [[ -x "$bin" ]] || die "no vlb binary found (looked at $(deployed_bin) and $VLB_BIN)"
        if [[ $EUID -ne 0 && -w "$bin" ]]; then
            warn "not root: the binary can be replaced but the service cannot be restarted"
        fi
        exec "$bin" --config "$VLB_CONFIG" update "$@"
    fi

    # ── from the checkout ────────────────────────────────────────────────
    [[ $EUID -eq 0 ]] || die "updating deploys a binary and restarts the service; run it with sudo"
    command -v git >/dev/null || die "git is not installed, so this checkout cannot be updated"

    local deployed; deployed=$(deployed_bin)
    # Who owns the checkout, if anybody this machine can name.
    #
    # Running git as the owner keeps root out of their .git and off their
    # index. But a bind mount, an NFS export or a container can present a uid
    # with no passwd entry, and `stat` then says UNKNOWN — at which point
    # `sudo -u UNKNOWN` fails and the whole update stops before it has done
    # anything. Fall back to root there, telling git the directory is not
    # dubious, rather than refusing to update at all.
    local owner; owner=$(stat -c '%U' "$REPO_DIR" 2>/dev/null || echo root)
    if [[ -z "$owner" || "$owner" == UNKNOWN ]] || ! id "$owner" >/dev/null 2>&1; then
        [[ "$owner" != root ]] && \
            warn "the checkout's owner is not a user this machine knows; running git as root"
        owner=root
    fi
    local backup="${deployed}.previous"
    local before after
    before=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null) \
        || die "${REPO_DIR} is not a git checkout"

    log "updating from the checkout"
    log "at ${before:0:9}, deployed binary ${deployed}"

    # (1) A dirty tree is the operator's, not ours to discard.
    if ! git -C "$REPO_DIR" diff --quiet || ! git -C "$REPO_DIR" diff --cached --quiet; then
        warn "the checkout has uncommitted changes:"
        git -C "$REPO_DIR" status --short | sed 's/^/    /'
        die "commit or discard them first — refusing to build something that is not in git"
    fi

    # (2) Fetch. A failure here has changed nothing.
    local pull_out
    if ! pull_out=$(as_owner "$owner" pull --ff-only 2>&1); then
        printf '%s\n' "$pull_out" | sed 's/^/    /'
        die "git pull failed — nothing was changed"
    fi
    after=$(git -C "$REPO_DIR" rev-parse HEAD)
    if [[ "$before" == "$after" ]]; then
        # Not "nothing to do".
        #
        # An operator who ran `git pull` by hand first — which is what the
        # old instructions told them to do — arrives here with a checkout
        # that is current and a *deployed binary that is not*. Returning at
        # this point is what left this gateway running a build from before
        # the sources it was sitting on, with no sign that anything was
        # wrong. What matters is whether the deployed binary matches the
        # checkout, and that is decided after the build, below.
        log "the checkout is already at ${after:0:9}; checking what is deployed"
    else
        log "now at ${after:0:9}"
        git -C "$REPO_DIR" --no-pager log --oneline "${before}..${after}" | sed 's/^/    /'
    fi

    # (3) Build. Still nothing deployed, so a failure only rewinds the source.
    log "building"
    local build_out
    if ! build_out=$(VLB_NO_RESTART=1 bash "${BASH_SOURCE[0]}" build 2>&1); then
        printf '%s\n' "$build_out" | tail -n 25 | sed 's/^/    /'
        warn "the new sources do not build — rewinding the checkout to ${before:0:9}"
        as_owner "$owner" reset --hard "$before" >/dev/null 2>&1 \
            || warn "could not rewind the checkout; it is left at ${after:0:9}"
        die "update aborted: the build failed. The gateway is untouched and still running the previous version."
    fi
    [[ -x "$VLB_BIN" ]] || die "the build reported success but produced no ${VLB_BIN}"

    # Is what is deployed already what this checkout builds?
    if [[ -x "$deployed" ]] && cmp -s "$VLB_BIN" "$deployed"; then
        # The binary being current does not mean the daemon is running it.
        local want running
        want=$(binary_version "$deployed")
        running=$(running_version "$deployed")
        if [[ -n "$running" && -n "$want" && "$running" != "$want" ]]; then
            warn "${deployed} is ${want}, but the daemon answering is ${running}"
            warn "it was never restarted onto the current binary — doing that now"
            restart_daemon_now || true
            if wait_until_version "$deployed" "$want" 30; then
                ok "the daemon is now running ${want}"
            else
                warn "the daemon still reports $(running_version "$deployed")"
                failure_reason | sed 's/^/    /'
                die "could not get the daemon onto ${want}"
            fi
            return 0
        fi
        ok "already up to date: ${deployed} is what ${after:0:9} builds, and it is running"
        return 0
    fi

    # (4) Does the new binary accept this machine's configuration? A config
    #     the daemon rejects is a gateway that does not come back.
    local check_out
    if ! check_out=$("$VLB_BIN" --config "$VLB_CONFIG" check 2>&1); then
        printf '%s\n' "$check_out" | tail -n 20 | sed 's/^/    /'
        warn "rewinding the checkout to ${before:0:9}"
        as_owner "$owner" reset --hard "$before" >/dev/null 2>&1 || true
        die "update aborted: the new build rejects ${VLB_CONFIG}. The gateway is untouched."
    fi
    ok "the new build accepts ${VLB_CONFIG}"

    # (5) Deploy, keeping the binary we are replacing.
    if [[ -x "$deployed" ]]; then
        cp -a "$deployed" "$backup" || die "could not save the current binary to ${backup}"
        log "previous binary kept at ${backup}"
    fi
    install -m 0755 "$VLB_BIN" "$deployed" || die "could not install to ${deployed}"
    ok "deployed $("$deployed" --version 2>/dev/null || echo "the new build") to ${deployed}"

    # (6) Restart and wait for the NEW version to answer. This is the point
    #     of no return for the old binary, so everything after it can roll
    #     back.
    local want; want=$(binary_version "$deployed")
    restart_daemon_now || true

    if [[ -n "$want" ]] && wait_until_version "$deployed" "$want" 30; then
        ok "the daemon is running ${want}"
        log "  the previous binary is still at ${backup} if you want it back"
        return 0
    fi
    if [[ -z "$want" ]] && wait_until_serving 30 "$deployed"; then
        # No version to compare against; an answer is the best we have.
        ok "the new version is serving"
        log "  the previous binary is still at ${backup} if you want it back"
        return 0
    fi

    # (7) It did not come back as the new version. Put the old one in and say
    #     why. This also catches a restart that silently did not happen: the
    #     previous daemon answers, but it answers with the previous version.
    local running; running=$(running_version "$deployed")
    if [[ -n "$running" ]]; then
        warn "the daemon is answering, but it reports ${running}, not ${want:-the new build}"
    else
        warn "the new version did not answer within 30s"
    fi
    echo
    warn "  why it failed, from the log:"
    failure_reason | sed 's/^/    /'
    echo

    if [[ -f "$backup" ]]; then
        log "rolling back to the previous binary"
        install -m 0755 "$backup" "$deployed" || die "ROLLBACK FAILED: could not restore ${deployed} from ${backup} — restore it by hand and restart ${VLB_SERVICE}"
        restart_daemon_now || true
        if wait_until_serving 30 "$deployed"; then
            ok "rolled back — the gateway is serving the previous version again"
        else
            warn "the previous version did not come back either; the gateway may be down"
            warn "  look at:  journalctl -u ${VLB_SERVICE} -n 50"
        fi
    else
        warn "there was no previous binary at ${backup} to roll back to"
    fi

    warn "the checkout is left at ${after:0:9}; rewind it with:  git -C ${REPO_DIR} reset --hard ${before:0:9}"
    die "update failed and was rolled back — the reason is above"
}
cmd_test() {
    # Everything that can run without root or docker, first.
    require_cargo
    local lab=0
    for a in "$@"; do [[ "$a" == "--lab" ]] && lab=1; done

    log "cargo fmt --check"
    cargo fmt --all -- --check || die "formatting differs; run: cargo fmt --all"
    ok "formatting clean"

    log "cargo clippy -D warnings"
    cargo clippy --release --all-targets --locked -- -D warnings || die "clippy found problems"
    ok "clippy clean"

    log "cargo test"
    cargo test --release --locked || die "unit tests failed"
    ok "unit tests passed"

    # The config that ships must itself be valid — a broken example is a
    # broken first-run experience.
    log "validating examples/vlb.example.toml"
    cargo run --release --locked --quiet -- --config examples/vlb.example.toml check >/dev/null \
        || die "examples/vlb.example.toml does not validate"
    ok "example config validates"

    if [[ $lab -eq 1 ]]; then
        command -v docker >/dev/null || die "docker not found; --lab needs it"
        log "running the docker failover lab (this takes a few minutes)"
        bash "${REPO_DIR}/docker/test/run-tests.sh" || die "failover lab failed"
        ok "failover lab passed"
    else
        log "skipping the docker failover lab (pass --lab to include it)"
    fi

    ok "all checks passed — safe to push"
}

# Print the header comment as the help text. Derived from the file rather
# than from a hard-coded line range, which silently went stale every time a
# command was added.
cmd_help() {
    awk 'NR > 1 { if (/^#/) { sub(/^# ?/, ""); print } else { exit } }' "$0"
}

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
        probe)              cmd_probe "$@" ;;
        clients)            cmd_clients "$@" ;;
        update)             cmd_update "$@" ;;
        test)               cmd_test "$@" ;;
        logs)               cmd_logs ;;
        install)            cmd_install "$@" ;;
        install-service)    cmd_install_service ;;
        uninstall-service)  cmd_uninstall_service ;;
        -h|--help|help)     cmd_help ;;
        *) die "unknown command: $cmd (try: $0 help)" ;;
    esac
}

main "$@"
