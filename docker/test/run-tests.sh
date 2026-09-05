#!/usr/bin/env bash
# Failover scenario suite.
#
# Each scenario breaks one of the simulated ISPs in a specific way and asserts
# that vlb reaches the right conclusion within a deadline. The headline case is
# `expired`: the provider stays fully reachable — the next hop pings, external
# IPs ping, DNS answers — while intercepting all traffic. That combination used
# to leave vlb sitting happily on a dead uplink, and it is the reason the
# content canary exists.
#
# Usage:
#   ./run-tests.sh              run everything
#   ./run-tests.sh expired      run one scenario by name
#   ./run-tests.sh --keep       leave the lab running afterwards for poking at
set -uo pipefail
# `eventually` matches with case globs, and some patterns use @(a|b).
shopt -s extglob

# Git Bash / MSYS rewrites arguments that look like absolute POSIX paths into
# Windows paths, which turns `/etc/vlb/vlb.toml` into `C:/Program Files/...`
# before docker ever sees it. Harmless to set on Linux, essential on Windows.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")" || exit 2

COMPOSE=(docker compose -f docker-compose.yml)
KEEP=0
FILTER=""
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        -*) echo "unknown flag $arg" >&2; exit 2 ;;
        *) FILTER="$arg" ;;
    esac
done

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; DIM=$'\033[2m'; RST=$'\033[0m'
PASS=0; FAIL=0; FAILED_NAMES=()

say()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '  %sPASS%s %s\n' "$GRN" "$RST" "$*"; PASS=$((PASS+1)); }
bad()  { printf '  %sFAIL%s %s\n' "$RED" "$RST" "$*"; FAIL=$((FAIL+1)); FAILED_NAMES+=("$*"); }
note() { printf '  %s%s%s\n' "$DIM" "$*" "$RST"; }

vlb_exec() { "${COMPOSE[@]}" exec -T vlb "$@" 2>/dev/null; }
isp_mode() { "${COMPOSE[@]}" exec -T "$1" isp-mode "$2" >/dev/null 2>&1; }

# Parse the daemon's JSON status with a real JSON parser rather than
# grep/cut. The pretty-printed output leaves a trailing comma on every value,
# which a naive `cut -d:` cheerfully returns as part of the provider name --
# so every wait loop silently never matched.
status_json() { vlb_exec vlb --config /etc/vlb/vlb.toml status 2>/dev/null; }

PY=$(command -v python3 || command -v python)
[ -n "$PY" ] || { echo "python3 is required to run these tests" >&2; exit 2; }

# The provider vlb currently has installed as the default route.
active_provider() {
    status_json | "$PY" -c "
import json,sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
print(d.get('snapshot', {}).get('active') or '')
"
}

# One field out of one provider's snapshot entry.
provider_field() {
    status_json | "$PY" -c "
import json,sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
for p in d.get('snapshot', {}).get('providers', []):
    if p['name'] == '$1':
        v = p.get('$2')
        # A bare 'or' default would swallow legitimate falsy values: priority 0
        # is the primary provider, and printing it as empty made the
        # priority-gap assertion fail against correct behaviour.
        print('' if v is None else v)
"
}

# One top-level field of the snapshot (`active_adopted`, `forced`, …).
# Non-strings are printed as JSON so booleans read `true`/`false` and an
# absent value reads `null`, which is what the assertions below match on.
snapshot_field() {
    status_json | "$PY" -c "
import json,sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
v = d.get('snapshot', {}).get('$1')
print(v if isinstance(v, str) else json.dumps(v))
"
}

# How many times a line matching the pattern has appeared in the daemon's
# log so far. Compared before/after an action, so history does not count.
log_count() {
    local n
    n=$("${COMPOSE[@]}" logs vlb 2>&1 | grep -c -- "$1" || true)
    printf '%s' "${n:-0}"
}

# Restart the daemon *process* in place — what systemd's Restart=always (and
# an update) does on a real box. The container, and with it the network
# namespace and every route in it, stays as it is. Waits for the new process
# to answer on the control socket.
restart_daemon() {
    local old_pid new_pid
    old_pid=$(vlb_exec sh -c 'pgrep -x vlb | head -1' | tr -d '[:space:]')
    vlb_exec sh -c 'pkill -TERM -x vlb' >/dev/null 2>&1
    local waited=0
    while [ "$waited" -lt 30 ]; do
        sleep 1; waited=$((waited+1))
        new_pid=$(vlb_exec sh -c 'pgrep -x vlb | head -1' | tr -d '[:space:]')
        [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] || continue
        if status_json | grep -q '"active"'; then
            printf '%s' "$waited"
            return 0
        fi
    done
    printf '%s' "$waited"
    return 1
}

# The gateway the kernel is really using — the ground truth, independent of
# what vlb believes.
kernel_default_gw() {
    local out=""
    # `docker exec` occasionally returns nothing under load on a busy host.
    # An empty read is indistinguishable from "no default route at all", and
    # the two mean very different things — so retry a couple of times before
    # believing it.
    local try=0
    while [ "$try" -lt 3 ]; do
        out=$(vlb_exec ip -4 route show default)
        [ -n "$out" ] && break
        try=$((try+1)); sleep 1
    done
    # Lowest metric wins, as the kernel does it. Reading the first line is
    # only usually right: `ip route show` prints in kernel order, which is
    # not a promise, and a transient second default would then be reported
    # as the winner.
    printf '%s\n' "$out" | awk '
        /^default/ {
            metric = 0; gw = ""
            for (i = 1; i < NF; i++) {
                if ($i == "metric") metric = $(i+1)
                if ($i == "via")    gw     = $(i+1)
            }
            if (gw != "" && (best == "" || metric + 0 < bestm + 0)) {
                best = gw; bestm = metric
            }
        }
        END { print best }'
}

# Every default route on one line, for diagnosing a failure rather than
# guessing at one.
all_default_routes() {
    vlb_exec ip -4 route show default | tr '\n' ';'
}

# The gateway belonging to whichever provider vlb currently has active.
active_gateway() {
    local a; a=$(active_provider)
    [ -n "$a" ] || return 1
    provider_field "$a" gateway
}

# Poll until `active == $1`, or give up after $2 seconds.
wait_for_active() {
    local want="$1" deadline="$2" waited=0
    while [ "$waited" -lt "$deadline" ]; do
        if [ "$(active_provider)" = "$want" ]; then
            printf '%s' "$waited"
            return 0
        fi
        sleep 1
        waited=$((waited+1))
    done
    printf '%s' "$waited"
    return 1
}

# Can a LAN client actually reach the genuine origin content right now?
#
# Run from the `client` container rather than from vlb, and deliberately so:
# this is the only assertion that speaks for the people behind the gateway.
# It consults nothing vlb believes, and it exercises forwarding, NAT and the
# conntrack state a failover disturbs — none of which the gateway's own
# traffic touches.
real_traffic_works() {
    # Retry briefly rather than demanding the first request succeed. A
    # switchover flushes conntrack, so a request issued in that window is
    # legitimately reset; a user sees a moment's hiccup, not an outage.
    # Asserting on a single attempt would call correct behaviour a failure.
    local waited=0
    while [ "$waited" -lt 12 ]; do
        if "${COMPOSE[@]}" exec -T client \
            curl -s --max-time 5 http://192.0.2.10/canary.txt 2>/dev/null \
            | grep -q 'vlb-canary-v1-do-not-edit'; then
            return 0
        fi
        sleep 1
        waited=$((waited+1))
    done
    return 1
}

# Wait until `$1` has been the active provider for several consecutive
# seconds, not merely for one sample.
#
# A single reading is not enough at lab startup: the origin's nginx and
# dnsmasq are still warming up, so a probe can legitimately fail a few
# seconds after vlb first selects a provider. vlb then correctly fails over
# — and a scenario that began on the strength of that first sample sees the
# backup active and reports a failure that is really its own impatience.
wait_until_stable() {
    local want="$1" deadline="${2:-60}" need="${3:-4}"
    local waited=0 streak=0
    while [ "$waited" -lt "$deadline" ]; do
        if [ "$(active_provider)" = "$want" ]; then
            streak=$((streak+1))
            [ "$streak" -ge "$need" ] && { printf '%s' "$waited"; return 0; }
        else
            streak=0
        fi
        sleep 1
        waited=$((waited+1))
    done
    printf '%s' "$waited"
    return 1
}

# Poll a command until its output matches a glob, or a deadline passes.
#
# Assertions about *derived* state — the failure layer, a canary summary, the
# route the kernel settled on — are assertions about an eventually-consistent
# system. The daemon re-evaluates every few seconds and publishes the value
# when it gets there, not at the instant a test happens to look. Reading once
# turns ordinary convergence into a spurious failure, and worse, makes real
# regressions indistinguishable from timing noise.
#
# Prints whatever it last saw, so a genuine failure still says what the value
# actually was.
eventually() {
    local deadline="$1" pattern="$2"; shift 2
    local waited=0 out=""
    while [ "$waited" -lt "$deadline" ]; do
        out=$("$@" 2>/dev/null)
        # shellcheck disable=SC2254  # the glob is the point
        case "$out" in
            $pattern) printf '%s' "$out"; return 0 ;;
        esac
        sleep 1
        waited=$((waited+1))
    done
    printf '%s' "$out"
    return 1
}

reset_lab() {
    isp_mode isp1 good
    isp_mode isp2 good
    # Settle onto the primary *and stay there* before the next scenario runs.
    wait_until_stable isp-main 90 4 >/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────
# Scenarios
# ─────────────────────────────────────────────────────────────────────────

scenario_baseline() {
    info "baseline — both providers healthy, primary (priority 0) selected"
    reset_lab
    local a; a=$(active_provider)
    [ "$a" = "isp-main" ] && ok "active = isp-main" || bad "baseline: active = '$a', expected isp-main"
    if [ "$(kernel_default_gw)" = "10.77.0.2" ]; then
        ok "kernel default route points at isp-main"
    else
        bad "baseline: kernel default gw = $(kernel_default_gw), expected 10.77.0.2"
        note "all defaults: $(all_default_routes)"
    fi
    real_traffic_works && ok "real traffic reaches the origin" \
        || bad "baseline: real traffic does not reach the origin"
}

scenario_dead() {
    info "dead — the primary's router disappears entirely"
    reset_lab
    isp_mode isp1 dead
    local t; t=$(wait_for_active isp-backup 30)
    if [ "$(active_provider)" = "isp-backup" ]; then
        ok "failed over to isp-backup in ${t}s"
        real_traffic_works && ok "real traffic restored via the backup" \
            || bad "dead: failed over but traffic still broken"
    else
        bad "dead: no failover after ${t}s (active=$(active_provider))"
    fi
}

scenario_blackhole() {
    info "blackhole — the router answers pings but forwards nothing"
    reset_lab
    isp_mode isp1 blackhole
    local t; t=$(wait_for_active isp-backup 30)
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "failed over in ${t}s despite the gateway still answering ICMP" \
        || bad "blackhole: no failover after ${t}s"
}

scenario_dns_blocked() {
    info "dns-blocked — ICMP works end to end, UDP/53 is dropped"
    reset_lab
    isp_mode isp1 dns-blocked
    local t; t=$(wait_for_active isp-backup 30)
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "failed over in ${t}s on the DNS layer" \
        || bad "dns-blocked: no failover after ${t}s"
}

# The reason this whole feature exists.
scenario_expired() {
    info "expired — unpaid account: uplink reachable, all traffic intercepted"
    reset_lab
    note "the primary keeps answering pings and DNS; only the *content* is wrong"
    isp_mode isp1 expired

    # Prove the deception is real: the reachability layer still passes.
    if vlb_exec ping -c1 -W2 -n 10.77.0.2 >/dev/null 2>&1; then
        note "confirmed: the primary's next hop still answers ICMP"
    fi

    local t; t=$(wait_until_stable isp-backup 60 3)
    if [ "$(active_provider)" = "isp-backup" ]; then
        ok "detected interception and failed over in ${t}s"
    else
        bad "expired: NO FAILOVER after ${t}s — this is the production bug"
        return
    fi

    real_traffic_works && ok "real traffic restored via the backup" \
        || bad "expired: failed over but traffic still broken"

    # The reason must name content tampering, not a generic timeout: an
    # operator needs to know to call the ISP about the bill.
    local reason
    if reason=$(eventually 45 '@(content_tampered|dns_hijack)' provider_field isp-main failure_layer); then
        ok "failure attributed to '$reason'"
    else
        bad "expired: failure layer settled on '$reason', expected content_tampered/dns_hijack"
    fi
}

# Proves the canary is load-bearing on its own. Under `portal-http` the
# gateway pings, the internet pings, DNS resolves correctly AND answers
# NXDOMAIN for .invalid -- every layer except the content check is happy. If
# vlb still fails over, it can only be because it compared the bytes.
scenario_canary_only() {
    info "portal-http — HTTP intercepted, DNS honest: only the canary can see it"
    reset_lab
    isp_mode isp1 portal-http

    # Show that the cheaper layers really are satisfied.
    if vlb_exec ping -c1 -W2 -n 10.77.0.2 >/dev/null 2>&1; then
        note "next hop answers ICMP"
    fi

    local t; t=$(wait_until_stable isp-backup 60 3)
    if [ "$(active_provider)" != "isp-backup" ]; then
        bad "portal-http: no failover after ${t}s — the canary is not carrying its weight"
        return
    fi
    ok "content canary alone detected the intercept and failed over in ${t}s"

    local layer
    if layer=$(eventually 45 'content_tampered' provider_field isp-main failure_layer); then
        ok "attributed to content_tampered (not the DNS layer)"
    else
        bad "portal-http: layer settled on '$layer', expected content_tampered"
    fi

    local summary
    if summary=$(eventually 30 '*TAMPERED*' provider_field isp-main last_canary_summary); then
        ok "canary summary names the tampering"
    else
        bad "portal-http: canary summary never named it: $summary"
    fi

    real_traffic_works && ok "real traffic restored via the backup" \
        || bad "portal-http: failed over but traffic still broken"
}

# The mode no reachability check can see.
#
# The provider applies a rate limit instead of redirecting or dropping. Every
# other layer passes: the next hop answers ICMP, DNS resolves honestly, and
# the content canary fetches the right bytes -- because a rate limiter is a
# token bucket and a 1.2 KB file fits inside the burst allowance, arriving at
# full line speed. Only moving enough bytes to drain the bucket reveals it.
scenario_throttled() {
    info "throttled — link up, everything reachable, 64 kbit/s"
    reset_lab
    isp_mode isp1 throttled

    # Show the deception is real before asserting on the fix.
    note "small probes still sail through the rate limiter's burst:"
    vlb_exec curl -s --max-time 10 -o /dev/null \
        -w "      1.2 KB canary file: %{time_total}s\n" \
        http://192.0.2.10/canary.txt 2>/dev/null || true
    vlb_exec curl -s --max-time 30 -o /dev/null \
        -w "      256 KB transfer   : %{time_total}s at %{speed_download} B/s\n" \
        http://192.0.2.10/big.bin 2>/dev/null || true

    local t; t=$(wait_until_stable isp-backup 90 3)
    if [ "$(active_provider)" != "isp-backup" ]; then
        bad "throttled: NO FAILOVER after ${t}s — a 64 kbit/s link is being treated as healthy"
        return
    fi
    ok "detected the throttle and failed over in ${t}s"

    local layer
    if layer=$(eventually 60 'throttled' provider_field isp-main failure_layer); then
        ok "attributed to 'throttled', not a vague timeout"
    else
        bad "throttled: layer settled on '$layer', expected throttled"
    fi

    local summary
    if summary=$(eventually 30 '*kbit/s*' provider_field isp-main last_throughput_summary); then
        ok "reported the measured rate: ${summary%% (*}"
    else
        bad "throttled: no throughput figure reported (got: $summary)"
    fi

    real_traffic_works && ok "real traffic restored via the backup" \
        || bad "throttled: failed over but traffic still broken"
}

# The operator asked for this one explicitly: priorities 0 and 2, nothing at
# 1. The gap must not confuse ordering in either direction.
scenario_priority_gap() {
    info "priority gap — 0 and 2 with no 1 in between"
    reset_lab

    local p0 p2
    p0=$(provider_field isp-main priority)
    p2=$(provider_field isp-backup priority)
    [ "$p0" = "0" ] && [ "$p2" = "2" ] \
        && ok "configured as priority 0 and 2, with 1 deliberately absent" \
        || bad "priority-gap: expected 0 and 2, got '$p0' and '$p2'"

    [ "$(active_provider)" = "isp-main" ] \
        && ok "lowest number wins while both are healthy" \
        || bad "priority-gap: expected isp-main, got $(active_provider)"

    # Down the priority-0 provider: the only candidate left is at priority 2.
    # Nothing occupies 1, so a naive "next priority" walk would find nothing.
    isp_mode isp1 dead
    local t; t=$(wait_for_active isp-backup 40)
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "skipped the empty priority 1 and took priority 2 in ${t}s" \
        || bad "priority-gap: did not fall through to priority 2 after ${t}s"
    real_traffic_works && ok "traffic flows through the priority-2 provider" \
        || bad "priority-gap: traffic broken on the backup"

    # And back up again, to prove the gap does not break the return path.
    isp_mode isp1 good
    t=$(wait_for_active isp-main 60)
    [ "$(active_provider)" = "isp-main" ] \
        && ok "returned to priority 0 in ${t}s once it recovered" \
        || bad "priority-gap: never returned to priority 0 (${t}s)"

    # Kernel routing tables are derived from the priority, so the gap has to
    # show up there too rather than collapsing onto one table.
    if vlb_exec ip route show table 200 | grep -q default \
       && vlb_exec ip route show table 202 | grep -q default; then
        ok "tables 200 and 202 both populated (201 unused, as intended)"
    else
        bad "priority-gap: expected routing tables 200 and 202 to exist"
    fi
}

scenario_failback() {
    info "failback — the primary recovers and must be reclaimed, but not instantly"
    reset_lab
    isp_mode isp1 expired
    wait_for_active isp-backup 40 >/dev/null
    [ "$(active_provider)" = "isp-backup" ] || { bad "failback: setup failed"; return; }

    isp_mode isp1 good
    # failback_stable_secs = 6 in the test config, so an immediate switch
    # would mean the stability window is not being honoured.
    sleep 2
    if [ "$(active_provider)" = "isp-main" ]; then
        bad "failback: switched back after ~2s, ignoring the 6s stability window"
    else
        ok "held on the backup while the primary proved itself"
    fi

    local t; t=$(wait_for_active isp-main 40)
    [ "$(active_provider)" = "isp-main" ] \
        && ok "failed back to the primary after ${t}s" \
        || bad "failback: never returned to the primary (${t}s)"
    real_traffic_works && ok "real traffic works on the reclaimed primary" \
        || bad "failback: traffic broken after failback"
}

scenario_both_down() {
    info "both down — no healthy provider anywhere"
    reset_lab
    isp_mode isp1 dead
    isp_mode isp2 dead
    sleep 12
    # The daemon must survive this and keep serving status, rather than
    # panicking or tearing the route down and losing even partial service.
    if vlb_exec vlb --config /etc/vlb/vlb.toml status >/dev/null 2>&1; then
        ok "daemon stayed alive and responsive with nothing healthy"
    else
        bad "both-down: the daemon stopped answering the control socket"
    fi
    if vlb_exec ip -4 route show default | grep -q default; then
        ok "kept the last-known default route instead of removing it"
    else
        bad "both-down: default route was removed, guaranteeing a black hole"
    fi

    isp_mode isp2 good
    local t; t=$(wait_for_active isp-backup 40)
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "recovered onto the backup in ${t}s once it returned" \
        || bad "both-down: did not recover after ${t}s"
}

# Models the operator's own update: the daemon is restarted while everything
# is healthy. Nothing about the network changed, so the route must stay put
# and traffic must keep flowing. This is the moment an operator is most
# likely to be watching, and the least forgiving of a needless disruption.
scenario_restart() {
    info "daemon restart — an update must not disturb a healthy gateway"
    reset_lab
    [ "$(active_provider)" = "isp-main" ] || { bad "restart: setup failed"; return; }

    # Establish a long-lived flow through the gateway first. If the restart
    # flushes conntrack, this connection dies; if it does not, it survives.
    "${COMPOSE[@]}" exec -T -d vlb sh -c \
        'curl -s --max-time 45 -o /tmp/slow.out http://192.0.2.10/canary.txt >/dev/null 2>&1; \
         nc -w 40 192.0.2.10 80 >/dev/null 2>&1 &' >/dev/null 2>&1 || true

    local before_gw; before_gw=$(kernel_default_gw)

    "${COMPOSE[@]}" restart vlb >/dev/null 2>&1
    local t; t=$(wait_for_active isp-main 45)
    if [ "$(active_provider)" != "isp-main" ]; then
        bad "restart: daemon did not come back onto isp-main after ${t}s"
        return
    fi
    ok "came back on the same provider in ${t}s"

    [ "$(kernel_default_gw)" = "$before_gw" ] \
        && ok "default route unchanged across the restart ($before_gw)" \
        || bad "restart: route moved from $before_gw to $(kernel_default_gw)"

    real_traffic_works && ok "traffic works immediately after the restart" \
        || bad "restart: traffic broken after the restart"

    # The daemon logs whether it skipped the flush. That line is the actual
    # assertion -- conntrack counts on a near-idle lab are too noisy to
    # compare directly.
    if "${COMPOSE[@]}" logs --tail 200 vlb 2>&1 | grep -q "skipping the conntrack flush"; then
        ok "recognised the route was already correct and skipped the flush"
    else
        # Not fatal on its own: with RUST_LOG=info the debug line is absent.
        note "flush-skip line not in the log (expected at RUST_LOG=debug)"
    fi
}

# The update, as it actually happens on a live box: the process is
# restarted while the routes it installed stay in the kernel. The new
# process must take that route over rather than start from nothing.
#
# The primary is made *slower* than the backup first. Without adoption the
# first provider to finish its probe rounds won the initial selection, and
# on links of unequal speed that was the backup — the gateway then moved all
# traffic to the backup, flushed conntrack, and thirty seconds later moved
# it back and flushed again. Two outages, caused by an update, on a network
# where nothing was wrong.
scenario_restart_slow_primary() {
    info "daemon restart with a slower primary — the faster backup must not win"
    reset_lab
    isp_mode isp1 slow
    if ! wait_until_stable isp-main 60 3 >/dev/null; then
        bad "restart-slow: the primary did not stay active with 60 ms of added latency"
        return
    fi
    local before_gw; before_gw=$(kernel_default_gw)
    local adopted_before; adopted_before=$(log_count "adopted the installed default route")
    local failovers_before; failovers_before=$(log_count "FAILOVER")

    local t
    if ! t=$(restart_daemon); then
        bad "restart-slow: the daemon did not come back within ${t}s"
        return
    fi
    ok "daemon back in ${t}s"

    # Watch the window in which the race used to happen: the backup's second
    # round finishes well before the primary's.
    local waited=0 flipped=0 moved=0
    while [ "$waited" -lt 20 ]; do
        [ "$(active_provider)" = "isp-backup" ] && flipped=1
        [ "$(kernel_default_gw)" != "$before_gw" ] && moved=1
        sleep 1; waited=$((waited+1))
    done
    [ "$flipped" -eq 0 ] \
        && ok "never switched to the faster backup after the restart" \
        || bad "restart-slow: switched to isp-backup after the restart — the initial-selection race"
    [ "$moved" -eq 0 ] \
        && ok "default route never moved ($before_gw)" \
        || bad "restart-slow: the default route moved during the restart"

    local adopted_after; adopted_after=$(log_count "adopted the installed default route")
    [ "$adopted_after" -gt "$adopted_before" ] \
        && ok "the new process adopted the installed route as its incumbent" \
        || bad "restart-slow: no adoption logged"

    local failovers_after; failovers_after=$(log_count "FAILOVER")
    [ "$failovers_after" -eq "$failovers_before" ] \
        && ok "no switchover logged — verified in place, nothing flushed" \
        || bad "restart-slow: a FAILOVER was logged across the restart"

    local adopted
    if adopted=$(eventually 30 'false' snapshot_field active_adopted); then
        ok "adopted route verified by the new process's own probes"
    else
        bad "restart-slow: route still unverified after 30s (active_adopted=$adopted)"
    fi
    real_traffic_works && ok "client traffic flowed throughout" \
        || bad "restart-slow: client traffic broken after the restart"
}

# The other half: restarting while failed over. The backup is carrying the
# traffic; the primary is dead. The new process must come back *on the
# backup*, at once, without re-deciding — and the primary's return must
# still go through the failback window.
scenario_restart_on_backup() {
    info "daemon restart while failed over — the backup route is adopted, not re-chosen"
    reset_lab
    isp_mode isp1 dead
    wait_for_active isp-backup 40 >/dev/null
    [ "$(active_provider)" = "isp-backup" ] || { bad "restart-on-backup: setup failed"; return; }
    local before_gw; before_gw=$(kernel_default_gw)
    local failovers_before; failovers_before=$(log_count "FAILOVER")

    local t
    if ! t=$(restart_daemon); then
        bad "restart-on-backup: the daemon did not come back within ${t}s"
        return
    fi
    local a; a=$(active_provider)
    [ "$a" = "isp-backup" ] \
        && ok "back on isp-backup immediately (${t}s, adopted)" \
        || bad "restart-on-backup: active='$a' right after the restart"
    [ "$(kernel_default_gw)" = "$before_gw" ] \
        && ok "default route unchanged ($before_gw)" \
        || bad "restart-on-backup: route moved to $(kernel_default_gw)"

    local adopted
    if adopted=$(eventually 30 'false' snapshot_field active_adopted); then
        ok "backup verified in place by the new process"
    else
        bad "restart-on-backup: still unverified after 30s (active_adopted=$adopted)"
    fi
    local failovers_after; failovers_after=$(log_count "FAILOVER")
    [ "$failovers_after" -eq "$failovers_before" ] \
        && ok "no switchover logged — no conntrack flush across the restart" \
        || bad "restart-on-backup: a FAILOVER was logged across the restart"
    real_traffic_works && ok "client traffic flows on the adopted backup" \
        || bad "restart-on-backup: client traffic broken"

    # The primary returns. Failback must still wait its window rather than
    # snapping back because the daemon is "new".
    isp_mode isp1 good
    sleep 2
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "held on the backup while the primary proved itself" \
        || bad "restart-on-backup: switched back within 2s, ignoring the stability window"
    t=$(wait_for_active isp-main 60)
    [ "$(active_provider)" = "isp-main" ] \
        && ok "failed back to the primary after ${t}s" \
        || bad "restart-on-backup: never returned to the primary (${t}s)"
}

# An operator's pin is the one piece of intent the daemon holds. It used to
# evaporate on restart — so an update quietly undid `vlb force`.
scenario_pin_survives_restart() {
    info "operator pin survives a daemon restart"
    reset_lab
    vlb_exec vlb --config /etc/vlb/vlb.toml force isp-backup >/dev/null 2>&1
    wait_for_active isp-backup 20 >/dev/null
    if [ "$(active_provider)" != "isp-backup" ]; then
        bad "pin-restart: the pin did not take effect"
        vlb_exec vlb --config /etc/vlb/vlb.toml auto >/dev/null 2>&1
        return
    fi

    local t
    if ! t=$(restart_daemon); then
        bad "pin-restart: the daemon did not come back within ${t}s"
        return
    fi
    local f
    if f=$(eventually 20 'isp-backup' snapshot_field forced); then
        ok "pin restored after the restart (forced = $f)"
    else
        bad "pin-restart: the pin was lost across the restart (forced = '$f')"
    fi
    if eventually 20 'isp-backup' active_provider >/dev/null; then
        ok "still carrying traffic on the pinned provider"
    else
        bad "pin-restart: left the pinned provider (active = $(active_provider))"
    fi
    "${COMPOSE[@]}" logs --tail 300 vlb 2>&1 | grep -q "operator pin restored" \
        && ok "the restore is logged, so it is not a surprise later" \
        || note "no 'pin restored' line found in the log"

    vlb_exec vlb --config /etc/vlb/vlb.toml auto >/dev/null 2>&1
    t=$(wait_for_active isp-main 40)
    [ "$(active_provider)" = "isp-main" ] \
        && ok "released the pin; back on the primary in ${t}s" \
        || bad "pin-restart: did not return to the primary after release (${t}s)"
    # The release must be durable too: a restart must not resurrect the pin.
    if restart_daemon >/dev/null; then
        f=$(eventually 15 'null' snapshot_field forced)
        [ "$f" = "null" ] \
            && ok "a released pin stays released across a restart" \
            || bad "pin-restart: a released pin came back after the restart (forced = $f)"
    fi
}

# A provider whose interface does not exist at startup — a NIC that is late
# to appear at boot, or one that was removed. Startup used to fail outright
# on it, which took the *other* providers down with it: the daemon that
# exists to survive one broken uplink would not start because of one.
scenario_missing_interface() {
    info "a provider on an interface that does not exist — startup must carry on"
    reset_lab
    if ! VLB_CONFIG=/etc/vlb/generated/vlb.ghost.toml "${COMPOSE[@]}" up -d vlb >/dev/null 2>&1; then
        bad "missing-iface: could not bring the daemon up with the variant config"
        return
    fi
    if wait_until_stable isp-main 90 3 >/dev/null; then
        ok "daemon started and selected isp-main despite the unusable third provider"
    else
        bad "missing-iface: no provider selected (active = $(active_provider))"
        note "$("${COMPOSE[@]}" logs --tail 20 vlb 2>&1)"
    fi
    local st
    if st=$(eventually 30 'down' provider_field isp-ghost state); then
        ok "the ghost provider is reported down, not silently skipped"
    else
        bad "missing-iface: ghost provider state is '$st', expected down"
    fi
    # The explanation is logged once at startup and again from the health
    # loop's first retry. Read the whole log rather than a tail, and give it
    # a moment: `compose logs` on a freshly recreated container has been
    # seen to come back empty on a loaded host.
    local explained=0 waited=0
    while [ "$waited" -lt 15 ]; do
        if "${COMPOSE[@]}" logs --tail 5000 vlb 2>&1 \
            | grep -qE "could not set up this provider's routing table yet|routing table still cannot be set up"; then
            explained=1
            break
        fi
        sleep 1; waited=$((waited+1))
    done
    if [ "$explained" -eq 1 ]; then
        ok "startup explained the unusable interface and carried on"
    else
        bad "missing-iface: startup did not explain the unusable interface"
        note "$("${COMPOSE[@]}" logs --tail 60 vlb 2>&1 | grep -iE 'ghost|eth7|routing table|prepar' | head -20)"
    fi
    real_traffic_works && ok "client traffic flows through the working providers" \
        || bad "missing-iface: client traffic broken"

    # Back to the standard config for the remaining scenarios.
    VLB_CONFIG=/etc/vlb/vlb.toml "${COMPOSE[@]}" up -d vlb >/dev/null 2>&1
    wait_until_stable isp-main 90 3 >/dev/null \
        || bad "missing-iface: the lab did not recover after restoring the standard config"
}

scenario_watchdog() {
    info "route watchdog — an external tool overwrites our default route"
    reset_lab
    # Simulate a DHCP renew / netplan apply stealing the default route.
    vlb_exec ip route replace default via 10.77.0.3 dev eth0 metric 0 proto dhcp >/dev/null 2>&1
    note "replaced the default route with a bogus one behind vlb's back"
    # The invariant is that the kernel route matches vlb's *current* choice,
    # not that it equals a fixed address. Hammering the routing table can
    # legitimately knock the primary's probes out, and vlb failing over in
    # response is correct behaviour — asserting on 10.77.0.2 would call that
    # a watchdog failure.
    local waited=0 gw="" want=""
    while [ "$waited" -lt 40 ]; do
        want=$(active_gateway)
        gw=$(kernel_default_gw)
        if [ -n "$want" ] && [ "$gw" = "$want" ]; then
            break
        fi
        sleep 1; waited=$((waited+1))
    done
    if [ -n "$want" ] && [ "$gw" = "$want" ]; then
        ok "watchdog reclaimed the route in ${waited}s (matches the active provider)"
    else
        bad "watchdog: kernel route '$gw' does not match the active provider's '$want'"
        note "all defaults: $(all_default_routes)"
    fi
}

# Ubuntu 24.04 runs netplan on top of systemd-networkd, and both write
# default routes. `netplan apply` and a DHCP lease renewal each rewrite them
# without asking, which is the single most likely way a live gateway loses
# vlb's choice. The metric-0 / proto-static scheme exists precisely so our
# route wins the kernel's lookup rather than merely coexisting with theirs.
scenario_netplan_fight() {
    info "netplan / networkd — competing default routes must not win"
    reset_lab
    # Whatever vlb chose, not a fixed address: see the watchdog scenario.
    local ours; ours=$(active_gateway)
    [ -n "$ours" ] || { bad "netplan-fight: no active provider to compare against"; return; }

    # The shapes netplan and dhclient actually produce, at the metrics they
    # actually use. Each is installed alongside ours, not instead of it.
    local -a competitors=(
        "proto dhcp metric 100"
        "proto static metric 100"
        "proto ra metric 1024"
        "proto kernel metric 0"
        "proto dhcp metric 0"
        "proto boot metric 0"
        "proto ra metric 0"
    )
    local bad_gw="10.77.0.3"

    for spec in "${competitors[@]}"; do
        vlb_exec ip route add default via "$bad_gw" dev eth0 $spec >/dev/null 2>&1 \
            || vlb_exec ip route replace default via "$bad_gw" dev eth0 $spec >/dev/null 2>&1

        # The guarantee is "reclaimed within one watchdog period", not
        # "instantly": a rival appearing between ticks is precisely what the
        # watchdog exists to catch. The lab runs it every 5 s.
        local waited=0
        while [ "$waited" -lt 20 ]; do
            [ "$(kernel_default_gw)" = "$ours" ] && break
            sleep 1; waited=$((waited+1))
        done
        local winner; winner=$(kernel_default_gw)
        if [ "$winner" = "$ours" ]; then
            ok "beat '$spec' (reclaimed in ${waited}s)"
        else
            bad "netplan-fight: '$spec' held the route after ${waited}s (kernel picked $winner)"
        fi
        vlb_exec ip route del default via "$bad_gw" dev eth0 $spec >/dev/null 2>&1 || true
    done

    # Now the harder case: something replaces ours outright, exactly as
    # `netplan apply` does. The watchdog has to notice and reclaim it.
    vlb_exec ip route replace default via "$bad_gw" dev eth0 metric 0 proto static >/dev/null 2>&1
    note "replaced our metric-0 route outright, as 'netplan apply' would"
    local waited=0
    while [ "$waited" -lt 25 ]; do
        [ "$(kernel_default_gw)" = "$ours" ] && break
        sleep 1; waited=$((waited+1))
    done
    [ "$(kernel_default_gw)" = "$ours" ] \
        && ok "watchdog reclaimed the route in ${waited}s" \
        || bad "netplan-fight: route still $(kernel_default_gw) after ${waited}s"

    real_traffic_works && ok "client traffic unaffected throughout" \
        || bad "netplan-fight: client traffic broken"
}

# 60% packet loss. The interesting property is that a single-packet probe is
# a coin flip here, which is why the ICMP probe sends a burst and requires a
# majority of replies. A link this lossy is unusable and must fail over.
scenario_lossy() {
    info "lossy — 60% packet loss on the primary"
    reset_lab
    isp_mode isp1 lossy
    local t; t=$(wait_for_active isp-backup 60)
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "failed over in ${t}s despite probes intermittently succeeding" \
        || bad "lossy: no failover after ${t}s"
    real_traffic_works && ok "real traffic restored via the backup" \
        || bad "lossy: failed over but traffic still broken"
}

# conntrack is absent on a stock Ubuntu 24.04 server, and without it the
# post-failover flush silently does nothing: failover "works" while every
# established connection stays pinned to the dead provider until it times
# out. Silent degradation on a gateway is worse than a loud failure, so vlb
# has to say so at startup.
scenario_missing_conntrack() {
    info "missing conntrack — must be reported, not silently ignored"
    reset_lab

    "${COMPOSE[@]}" exec -T vlb sh -c 'mv /usr/sbin/conntrack /usr/sbin/conntrack.hidden 2>/dev/null \
        || mv /usr/bin/conntrack /usr/bin/conntrack.hidden 2>/dev/null' >/dev/null 2>&1

    local out
    out=$(vlb_exec vlb --config /etc/vlb/vlb.toml check 2>&1)
    case "$out" in
        *conntrack*)
            ok "vlb check names the missing tool and what it costs" ;;
        *)
            bad "missing-conntrack: 'vlb check' said nothing about it" ;;
    esac
    grep -qi "hang" <<<"$out" \
        && ok "explains the consequence, not just the absence" \
        || note "consequence text not found in check output"

    "${COMPOSE[@]}" exec -T vlb sh -c 'mv /usr/sbin/conntrack.hidden /usr/sbin/conntrack 2>/dev/null \
        || mv /usr/bin/conntrack.hidden /usr/bin/conntrack 2>/dev/null' >/dev/null 2>&1
    ok "restored conntrack for the remaining scenarios"
}

# An operator pinning a provider at the exact moment the daemon is failing
# over. Both write the routing table; the result must be coherent rather than
# whichever raced last, and the daemon must survive it.
scenario_concurrent_force() {
    info "concurrent operator commands during a failover"
    reset_lab
    isp_mode isp1 dead

    # Hammer force/auto while the health loop is switching underneath.
    for _ in $(seq 1 6); do
        vlb_exec vlb --config /etc/vlb/vlb.toml force isp-backup >/dev/null 2>&1 &
        vlb_exec vlb --config /etc/vlb/vlb.toml auto >/dev/null 2>&1 &
        vlb_exec vlb --config /etc/vlb/vlb.toml status >/dev/null 2>&1 &
    done
    wait 2>/dev/null || true
    sleep 6

    if vlb_exec vlb --config /etc/vlb/vlb.toml status >/dev/null 2>&1; then
        ok "daemon survived concurrent force/auto during a switchover"
    else
        bad "concurrent-force: daemon stopped answering"
        return
    fi

    # Exactly one default route, and it points at something real.
    local n; n=$(vlb_exec ip -4 route show default | grep -c "^default" || true)
    n=${n:-0}
    [ "$n" = "1" ] \
        && ok "exactly one default route installed (no duplicates from the race)" \
        || bad "concurrent-force: $n default routes present"

    vlb_exec vlb --config /etc/vlb/vlb.toml auto >/dev/null 2>&1
    isp_mode isp1 good
    local t; t=$(wait_for_active isp-main 60)
    [ "$(active_provider)" = "isp-main" ] \
        && ok "settled back onto the primary in ${t}s" \
        || bad "concurrent-force: did not settle (${t}s)"
    real_traffic_works && ok "client traffic works after the race" \
        || bad "concurrent-force: traffic broken"
}

# Repeated failovers, then a look at what the daemon is holding. A gateway
# runs for months untouched; a leak or an unbounded table is a slow outage.
scenario_soak() {
    info "soak — repeated failovers, then check the daemon is not growing"
    reset_lab

    local rss_before
    rss_before=$(vlb_exec sh -c 'ps -o rss= -C vlb 2>/dev/null | head -1' | tr -d ' ')
    [ -n "$rss_before" ] || rss_before=0
    note "RSS before: ${rss_before} KiB"

    local cycles=6
    for _ in $(seq 1 "$cycles"); do
        isp_mode isp1 dead
        wait_for_active isp-backup 40 >/dev/null || true
        isp_mode isp1 good
        wait_for_active isp-main 60 >/dev/null || true
    done
    ok "survived ${cycles} full failover/failback cycles"

    if ! vlb_exec vlb --config /etc/vlb/vlb.toml status >/dev/null 2>&1; then
        bad "soak: daemon stopped answering after ${cycles} cycles"
        return
    fi
    ok "still answering the control socket"

    local rss_after
    rss_after=$(vlb_exec sh -c 'ps -o rss= -C vlb 2>/dev/null | head -1' | tr -d ' ')
    [ -n "$rss_after" ] || rss_after=0
    note "RSS after : ${rss_after} KiB"

    # Generous: allocator behaviour and the stats DB cache make an exact
    # figure meaningless. The point is to catch a leak, not to police a few
    # hundred kilobytes.
    if [ "$rss_before" -gt 0 ] && [ "$rss_after" -gt 0 ]; then
        local limit=$(( rss_before * 3 + 20000 ))
        [ "$rss_after" -lt "$limit" ] \
            && ok "memory stable across cycles (${rss_before} -> ${rss_after} KiB)" \
            || bad "soak: RSS grew from ${rss_before} to ${rss_after} KiB"
    fi

    # Flap backoff should have kicked in and be visible, not silent.
    if "${COMPOSE[@]}" logs --tail 400 vlb 2>&1 | grep -qi "failback pending"; then
        ok "failback backoff engaged and logged during the flapping"
    else
        note "no failback-pending line (expected at RUST_LOG=debug)"
    fi

    real_traffic_works && ok "client traffic healthy at the end of the soak" \
        || bad "soak: traffic broken after the cycles"
}

scenario_force() {
    info "force / auto — operator pin overrides priority, then releases"
    reset_lab
    vlb_exec vlb --config /etc/vlb/vlb.toml force isp-backup >/dev/null 2>&1
    local t; t=$(wait_for_active isp-backup 20)
    [ "$(active_provider)" = "isp-backup" ] \
        && ok "pin moved the route to the backup in ${t}s" \
        || bad "force: pin did not take effect after ${t}s"

    vlb_exec vlb --config /etc/vlb/vlb.toml auto >/dev/null 2>&1
    t=$(wait_for_active isp-main 30)
    [ "$(active_provider)" = "isp-main" ] \
        && ok "releasing the pin returned to the primary in ${t}s" \
        || bad "force: did not return to the primary after ${t}s"
}

scenario_probe_cli() {
    info "vlb probe — per-layer timings and verdicts for each provider"
    reset_lab
    local out
    out=$(vlb_exec vlb --config /etc/vlb/vlb.toml probe 2>&1)
    grep -q "isp-main" <<<"$out" && grep -q "canary" <<<"$out" \
        && ok "probe reported both providers and the canary layer" \
        || { bad "probe: unexpected output"; note "$(head -5 <<<"$out")"; }

    isp_mode isp1 expired
    sleep 4
    out=$(vlb_exec vlb --config /etc/vlb/vlb.toml probe --provider isp-main 2>&1)
    grep -qi "tampered" <<<"$out" \
        && ok "probe named the interception explicitly" \
        || { bad "probe: did not report tampering under 'expired'"; note "$(head -20 <<<"$out")"; }
}

# ─────────────────────────────────────────────────────────────────────────

SCENARIOS=(baseline priority_gap dead blackhole lossy dns_blocked expired canary_only throttled failback both_down restart restart_slow_primary restart_on_backup pin_survives_restart missing_interface watchdog netplan_fight missing_conntrack concurrent_force soak force probe_cli)

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        say ""
        info "--keep given: the lab is still running."
        say "  logs:  docker compose -f docker/test/docker-compose.yml logs -f vlb"
        say "  shell: docker compose -f docker/test/docker-compose.yml exec vlb bash"
        say "  down:  docker compose -f docker/test/docker-compose.yml down -v"
    else
        # On a failure, the daemon's log is the only evidence there is, and
        # it goes down with the lab. Print it here, before the teardown: a
        # CI step that runs afterwards finds no containers to ask.
        if [ "${FAIL:-0}" -gt 0 ]; then
            say ""
            info "daemon log (last 250 lines) before teardown:"
            "${COMPOSE[@]}" logs --tail 250 vlb 2>&1 | sed 's/^/    /'
            say ""
        fi
        info "tearing the lab down"
        "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
    fi
}
trap cleanup EXIT

# A payload large enough to outlast any rate limiter's burst, used by the
# throttled scenario to show what real traffic experiences.
seed_origin_payload() {
    "${COMPOSE[@]}" exec -T origin sh -c \
        'test -f /var/www/origin/big.bin || head -c 262144 /dev/urandom > /var/www/origin/big.bin' \
        >/dev/null 2>&1 || true
}

# Variant configs, derived from the standard one so they never drift from
# it. Mounted read-only into the vlb container; the harness picks one with
# VLB_CONFIG when it brings the container up.
generate_variant_configs() {
    mkdir -p generated
    {
        cat vlb.test.toml
        cat <<'EOF'

# ── appended by run-tests.sh: a provider whose interface does not exist ──
[[providers]]
name = "isp-ghost"
gateway = "10.99.0.1"
interface = "eth7"
priority = 5
role = "backup"
EOF
    } > generated/vlb.ghost.toml
}
generate_variant_configs

info "building the lab"
if ! "${COMPOSE[@]}" build >/tmp/vlb-lab-build.log 2>&1; then
    say "${RED}build failed${RST} — last 40 lines:"
    tail -40 /tmp/vlb-lab-build.log
    exit 1
fi

info "starting the lab"
"${COMPOSE[@]}" up -d >/dev/null 2>&1

seed_origin_payload
info "waiting for vlb to settle on the primary"
if ! wait_until_stable isp-main 120 5 >/dev/null; then
    say "${RED}vlb never came up.${RST} Logs:"
    "${COMPOSE[@]}" logs --tail 60 vlb
    exit 1
fi
say ""

for s in "${SCENARIOS[@]}"; do
    if [ -n "$FILTER" ] && [ "$s" != "$FILTER" ] && [ "${s//_/-}" != "$FILTER" ]; then
        continue
    fi
    "scenario_$s"
    say ""
done

reset_lab >/dev/null 2>&1

say "────────────────────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
    printf '%sall %d assertions passed%s\n' "$GRN" "$PASS" "$RST"
else
    printf '%s%d passed, %d FAILED%s\n' "$YLW" "$PASS" "$FAIL" "$RST"
    for f in "${FAILED_NAMES[@]}"; do printf '  %s- %s%s\n' "$RED" "$f" "$RST"; done
fi
say "────────────────────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then exit 0; else exit 1; fi
