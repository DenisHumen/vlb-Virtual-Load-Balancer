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
        print(p.get('$2') or '')
"
}

# The gateway the kernel is really using — the ground truth, independent of
# what vlb believes.
kernel_default_gw() {
    vlb_exec ip -4 route show default | awk '/default/ {print $3; exit}'
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

# Can a client actually reach the genuine origin content right now? This is
# the end-to-end assertion: it does not consult vlb's opinion at all, it just
# asks whether real traffic works.
real_traffic_works() {
    vlb_exec curl -s --max-time 4 http://192.0.2.10/canary.txt 2>/dev/null \
        | grep -q 'vlb-canary-v1-do-not-edit'
}

reset_lab() {
    isp_mode isp1 good
    isp_mode isp2 good
    # Let the daemon settle back onto the primary before the next scenario.
    wait_for_active isp-main 40 >/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────
# Scenarios
# ─────────────────────────────────────────────────────────────────────────

scenario_baseline() {
    info "baseline — both providers healthy, primary (priority 0) selected"
    reset_lab
    local a; a=$(active_provider)
    [ "$a" = "isp-main" ] && ok "active = isp-main" || bad "baseline: active = '$a', expected isp-main"
    [ "$(kernel_default_gw)" = "10.77.0.2" ] \
        && ok "kernel default route points at isp-main" \
        || bad "baseline: kernel default gw = $(kernel_default_gw), expected 10.77.0.2"
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

    local t; t=$(wait_for_active isp-backup 40)
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
    reason=$(provider_field isp-main failure_layer)
    case "$reason" in
        content_tampered|dns_hijack)
            ok "failure attributed to '$reason'" ;;
        *)
            bad "expired: failure layer was '$reason', expected content_tampered/dns_hijack" ;;
    esac
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

    local t; t=$(wait_for_active isp-backup 40)
    if [ "$(active_provider)" != "isp-backup" ]; then
        bad "portal-http: no failover after ${t}s — the canary is not carrying its weight"
        return
    fi
    ok "content canary alone detected the intercept and failed over in ${t}s"

    local layer; layer=$(provider_field isp-main failure_layer)
    [ "$layer" = "content_tampered" ] \
        && ok "attributed to content_tampered (not the DNS layer)" \
        || bad "portal-http: layer was '$layer', expected content_tampered"

    local summary; summary=$(provider_field isp-main last_canary_summary)
    case "$summary" in
        *TAMPERED*) ok "canary summary names the tampering" ;;
        *) bad "portal-http: unexpected canary summary: $summary" ;;
    esac

    real_traffic_works && ok "real traffic restored via the backup" \
        || bad "portal-http: failed over but traffic still broken"
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
    local before_flows
    before_flows=$(vlb_exec conntrack -C 2>/dev/null | tr -d '[:space:]' || echo 0)

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

scenario_watchdog() {
    info "route watchdog — an external tool overwrites our default route"
    reset_lab
    # Simulate a DHCP renew / netplan apply stealing the default route.
    vlb_exec ip route replace default via 10.77.0.3 dev eth0 metric 0 proto dhcp >/dev/null 2>&1
    note "replaced the default route with a bogus one behind vlb's back"
    local waited=0
    while [ "$waited" -lt 25 ]; do
        [ "$(kernel_default_gw)" = "10.77.0.2" ] && break
        sleep 1; waited=$((waited+1))
    done
    [ "$(kernel_default_gw)" = "10.77.0.2" ] \
        && ok "watchdog restored the correct route in ${waited}s" \
        || bad "watchdog: route still $(kernel_default_gw) after ${waited}s"
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

SCENARIOS=(baseline dead blackhole dns_blocked expired canary_only failback both_down restart watchdog force probe_cli)

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        say ""
        info "--keep given: the lab is still running."
        say "  logs:  docker compose -f docker/test/docker-compose.yml logs -f vlb"
        say "  shell: docker compose -f docker/test/docker-compose.yml exec vlb bash"
        say "  down:  docker compose -f docker/test/docker-compose.yml down -v"
    else
        info "tearing the lab down"
        "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
    fi
}
trap cleanup EXIT

info "building the lab"
if ! "${COMPOSE[@]}" build >/tmp/vlb-lab-build.log 2>&1; then
    say "${RED}build failed${RST} — last 40 lines:"
    tail -40 /tmp/vlb-lab-build.log
    exit 1
fi

info "starting the lab"
"${COMPOSE[@]}" up -d >/dev/null 2>&1

info "waiting for vlb to select a provider"
if ! wait_for_active isp-main 60 >/dev/null; then
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
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
