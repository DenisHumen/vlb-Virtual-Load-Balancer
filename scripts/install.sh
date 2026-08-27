#!/usr/bin/env bash
#
# vlb installer / updater.
#
#   curl -fsSL https://raw.githubusercontent.com/DenisHumen/vlb-Virtual-Load-Balancer/main/scripts/install.sh | sudo bash
#
# Downloads the latest release for this machine's architecture, verifies it
# against the published SHA-256, installs it, and restarts the service.
# Safe to run repeatedly: it is the update path as well as the install path.
#
# It is written to be paranoid, because it replaces the binary that routes
# all of a site's traffic:
#
#   * the archive is checksum-verified before anything touches the disk;
#   * the new binary must run (`--version`) and must accept the *existing*
#     config before the old one is replaced -- a config the new build rejects
#     is caught while the working binary is still in place;
#   * the previous binary is kept, and restored automatically if the service
#     fails to come back;
#   * an existing /etc/vlb/vlb.toml is never overwritten.
#
# Environment overrides:
#   VLB_VERSION   install a specific tag (default: latest release)
#   VLB_PRE       set to 1 to consider pre-releases
#   VLB_REPO      owner/name (default: DenisHumen/vlb-Virtual-Load-Balancer)
#   VLB_NO_START  set to 1 to install without starting/restarting the service
#   VLB_SKIP_PROBE set to 1 to skip the pre-restart canary reachability check

set -Eeuo pipefail

REPO="${VLB_REPO:-DenisHumen/vlb-Virtual-Load-Balancer}"
BIN_PATH=/usr/local/bin/vlb
CONFIG_DIR=/etc/vlb
CONFIG_PATH="${CONFIG_DIR}/vlb.toml"
UNIT_PATH=/etc/systemd/system/vlb.service
SERVICE=vlb

# Adopt an existing deployment wherever it happens to live.
#
# The defaults above are what `install-service` sets up, but a box that was
# brought up by hand — say, running the binary straight out of a git checkout
# with a config beside it — will have neither. Installing to the default
# paths there would leave the *actual* running binary untouched: the update
# would report success and change nothing that matters.
#
# So if a unit already exists, believe it rather than the defaults, and read
# both paths out of its ExecStart line.
adopt_existing_unit() {
    local unit_file exec_line
    unit_file=$(systemctl show -p FragmentPath --value "$SERVICE" 2>/dev/null || true)
    [[ -n "$unit_file" && -r "$unit_file" ]] || return 0

    exec_line=$(systemctl show -p ExecStart --value "$SERVICE" 2>/dev/null || true)
    [[ -n "$exec_line" ]] || return 0

    UNIT_PATH="$unit_file"

    # ExecStart renders as `{ path=/usr/local/bin/vlb ; argv[]=... }`.
    local found_bin found_cfg
    found_bin=$(sed -n 's/.*path=\([^ ;]*\).*/\1/p' <<<"$exec_line" | head -1)
    found_cfg=$(grep -o -- '--config[= ][^ ;]*' <<<"$exec_line" \
                  | head -1 | sed 's/--config[= ]//' || true)

    if [[ -n "$found_bin" && "$found_bin" != "$BIN_PATH" ]]; then
        warn "the ${SERVICE} unit runs ${found_bin}, not ${BIN_PATH} — updating that instead"
        BIN_PATH="$found_bin"
    fi
    if [[ -n "$found_cfg" && "$found_cfg" != "$CONFIG_PATH" ]]; then
        log "the ${SERVICE} unit uses ${found_cfg} — keeping that config"
        CONFIG_PATH="$found_cfg"
        CONFIG_DIR=$(dirname "$found_cfg")
    fi
}

C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'; C_CYN=$'\033[0;36m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=; C_GRN=; C_YLW=; C_CYN=; C_RST=; }

# Every fetch this script makes ends up as root-owned bytes on the box, so
# the transport is pinned to HTTPS for the whole chain. `--proto-redir` is the
# half people forget: without it a redirect to plain http:// is followed
# happily, and the checksum travels the same chain so it would not save us.
CURL=(curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --retry-delay 2 --max-time 300)

log()  { printf '%s[vlb]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
ok()   { printf '%s[ ok]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!! ]%s %s\n' "$C_YLW" "$C_RST" "$*"; }
die()  { printf '%s[err]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

WORKDIR=""
cleanup() {
    if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
        rm -rf "$WORKDIR"
    fi
    return 0
}
trap cleanup EXIT

# ── preflight ────────────────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || die "must run as root — pipe this into 'sudo bash', or run 'sudo $0'"

for tool in curl tar sha256sum install; do
    command -v "$tool" >/dev/null || die "required tool '$tool' is not installed"
done

case "$(uname -s)" in
    Linux) ;;
    *) die "vlb is Linux-only (this host reports $(uname -s))" ;;
esac

# Releases are statically linked against musl, so the architecture is the
# only thing that varies. A glibc build would inherit the glibc version of
# the CI runner that produced it and refuse to start on older servers.
case "$(uname -m)" in
    x86_64|amd64)  TARGET=x86_64-unknown-linux-musl ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
    *) die "no published build for $(uname -m); build from source with 'cargo build --release'" ;;
esac

log "host: $(uname -m) → ${TARGET}"

# ── runtime dependencies ─────────────────────────────────────────────────
#
# vlb shells out to a handful of tools. Two of them are missing on a stock
# Ubuntu 24.04 server, and one of those fails *silently*: without
# `conntrack`, the flush after a switchover is a no-op, so failover looks
# like it worked while every established connection keeps pointing at the
# dead provider and hangs until it times out. Users experience a two-minute
# outage that no log line explains.
#
# So install them rather than merely warning. They are tiny, and a gateway
# that half-works is worse than one that tells you why.
ensure_runtime_deps() {
    local missing=()
    command -v ip        >/dev/null || missing+=(iproute2)
    command -v ping      >/dev/null || missing+=(iputils-ping)
    command -v iptables  >/dev/null || missing+=(iptables)
    command -v conntrack >/dev/null || missing+=(conntrack)

    [[ ${#missing[@]} -eq 0 ]] && { log "runtime dependencies present"; return 0; }

    log "installing missing runtime dependencies: ${missing[*]}"
    if command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
        if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null 2>&1; then
            ok "installed: ${missing[*]}"
            return 0
        fi
    elif command -v dnf >/dev/null; then
        dnf install -y -q "${missing[@]}" >/dev/null 2>&1 && { ok "installed: ${missing[*]}"; return 0; }
    elif command -v yum >/dev/null; then
        yum install -y -q "${missing[@]}" >/dev/null 2>&1 && { ok "installed: ${missing[*]}"; return 0; }
    fi

    warn "could not install: ${missing[*]}"
    for m in "${missing[@]}"; do
        case "$m" in
            conntrack)
                warn "  without conntrack, connections are NOT reset after a failover —" \
                     "they hang until they time out. Install it by hand." ;;
            iproute2|iputils-ping)
                die "  ${m} is required; vlb cannot run without it" ;;
        esac
    done
}
ensure_runtime_deps

if command -v systemctl >/dev/null; then
    adopt_existing_unit
fi

# ── locate the release ───────────────────────────────────────────────────

api() { "${CURL[@]}" -H 'Accept: application/vnd.github+json' "$@"; }

if [[ -n "${VLB_VERSION:-}" ]]; then
    TAG="$VLB_VERSION"
    log "requested version: ${TAG}"
else
    log "querying the latest release of ${REPO}"
    # /releases rather than /releases/latest so pre-releases are visible when
    # asked for; the API returns them newest-first.
    RELEASES_JSON=$(api "https://api.github.com/repos/${REPO}/releases?per_page=20") \
        || die "could not reach the GitHub API (no internet, or the repo is private)"

    # Pick the newest non-draft release, honouring VLB_PRE for pre-releases.
    # Parsed with grep/sed rather than jq, which is not installed by default
    # on a minimal server and would be an unnecessary prerequisite.
    # shellcheck disable=SC2020  # character sets, not words: both ',' and
    # '{' are deliberately mapped to a newline so each JSON key lands on its
    # own line for awk. Verified against a real 270 KB API response.
    TAG=$(printf '%s' "$RELEASES_JSON" \
        | tr ',{' '\n\n' \
        | awk -v want_pre="${VLB_PRE:-0}" '
            /"tag_name"/ { gsub(/.*"tag_name" *: *"/,""); gsub(/".*/,""); tag=$0 }
            /"draft"/    { draft = /true/ ? 1 : 0 }
            /"prerelease"/ {
                pre = /true/ ? 1 : 0
                if (tag != "" && draft == 0 && (want_pre == 1 || pre == 0)) { print tag; exit }
                tag=""
            }')
    [[ -n "$TAG" ]] || die "no published release found for ${REPO}. \
If only pre-releases exist, re-run with VLB_PRE=1."
    log "latest release: ${TAG}"
fi

ASSET="vlb-${TAG}-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

# ── current state ────────────────────────────────────────────────────────

CURRENT_VERSION=""
if [[ -x "$BIN_PATH" ]]; then
    CURRENT_VERSION=$("$BIN_PATH" --version 2>/dev/null | awk '{print $2}' || true)
    log "installed: ${CURRENT_VERSION:-unknown} at ${BIN_PATH}"
else
    log "no existing installation at ${BIN_PATH} — this is a fresh install"
fi

WAS_RUNNING=0
if command -v systemctl >/dev/null && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    WAS_RUNNING=1
    log "the ${SERVICE} service is currently running"
fi

# ── download and verify ──────────────────────────────────────────────────

WORKDIR=$(mktemp -d)
log "downloading ${ASSET}"
"${CURL[@]}" -o "${WORKDIR}/${ASSET}" "${BASE}/${ASSET}" \
    || die "download failed: ${BASE}/${ASSET}
Check that release ${TAG} publishes an asset for ${TARGET}."

log "verifying checksum"
"${CURL[@]}" -o "${WORKDIR}/${ASSET}.sha256" "${BASE}/${ASSET}.sha256" \
    || die "the release publishes no .sha256 for ${ASSET} — refusing to install an unverified binary"

EXPECTED=$(awk '{print $1; exit}' "${WORKDIR}/${ASSET}.sha256")
ACTUAL=$(sha256sum "${WORKDIR}/${ASSET}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || die "checksum mismatch!
  published:   ${EXPECTED}
  downloaded:  ${ACTUAL}
The download is corrupt or has been tampered with. Nothing was changed."
ok "sha256 verified (${ACTUAL:0:16}…)"

tar -xzf "${WORKDIR}/${ASSET}" -C "$WORKDIR" vlb || die "archive does not contain 'vlb'"
chmod 0755 "${WORKDIR}/vlb"

# Prove it runs on this machine before it replaces anything.
NEW_VERSION=$("${WORKDIR}/vlb" --version 2>/dev/null | awk '{print $2}') \
    || die "the downloaded binary does not execute on this host (wrong architecture, or missing libc)"
ok "downloaded binary runs: ${NEW_VERSION}"

if [[ -n "$CURRENT_VERSION" && "$CURRENT_VERSION" == "$NEW_VERSION" ]]; then
    log "already running ${NEW_VERSION}; reinstalling anyway to repair any drift"
fi

# ── config ───────────────────────────────────────────────────────────────

FRESH_CONFIG=0
if [[ -f "$CONFIG_PATH" ]]; then
    log "keeping the existing config at ${CONFIG_PATH}"
    # Validate with the NEW binary while the old one is still installed. A
    # release that tightened validation must not be discovered after the
    # restart, with the gateway already down.
    if ! "${WORKDIR}/vlb" --config "$CONFIG_PATH" check >"${WORKDIR}/check.out" 2>&1; then
        echo
        sed 's/^/    /' "${WORKDIR}/check.out" >&2
        echo
        die "the new build rejects your existing config (shown above).
Nothing was changed — ${BIN_PATH} is still ${CURRENT_VERSION:-the previous build}.
Fix ${CONFIG_PATH}, then re-run this installer."
    fi
    ok "existing config validates against ${NEW_VERSION}"

    # The canary is enabled by default, and it is the one new check that can
    # fail for reasons unrelated to your uplinks: a restrictive egress
    # firewall, or a region where one of the default endpoints is blocked. If
    # it cannot verify anything through *any* provider, restarting would mark
    # every provider unhealthy. Traffic would keep flowing on the installed
    # route -- nothing black-holes -- but automatic failover would quietly
    # stop working, which is precisely the thing you are installing this for.
    #
    # So find out before the restart, while the old binary is still serving.
    # Ask the *binary* whether the canary is on, rather than looking for a
    # [canary] section in the file. An existing config predates that section
    # entirely and will not contain it, while the canary still defaults to
    # enabled — so a grep over the config would skip this check on precisely
    # the deployments that most need it. `vlb check` prints the resolved
    # configuration, defaults included.
    CANARY_ON=1
    if grep -q 'DISABLED' "${WORKDIR}/check.out" 2>/dev/null; then
        CANARY_ON=0
        log "canary is disabled in this config — skipping the pre-flight"
    fi

    if [[ "${VLB_SKIP_PROBE:-0}" != "1" && $CANARY_ON -eq 1 ]]; then
        log "checking the content canary can reach its targets (pre-flight)"
        PROBE_OUT="${WORKDIR}/probe.out"
        if "${WORKDIR}/vlb" --config "$CONFIG_PATH" probe >"$PROBE_OUT" 2>&1; then
            if grep -q 'canary verdict: [1-9][0-9]*/' "$PROBE_OUT"; then
                VERIFIED=$(grep -o 'canary verdict: [0-9]*/[0-9]* canary targets verified' "$PROBE_OUT" | head -1)
                ok "canary pre-flight passed (${VERIFIED:-verified})"
            else
                echo
                grep -E 'canary|TAMPERED|unreach' "$PROBE_OUT" | sed 's/^/    /' >&2 || true
                echo
                die "the content canary did not meet its quorum through any provider
(output above). Restarting now would mark every provider unhealthy and switch
automatic failover off, while the currently installed binary keeps working.

Nothing was changed. Pick one:
  * open egress so the canary targets are reachable from this box; or
  * point [[canary.targets]] in ${CONFIG_PATH} at endpoints you can reach
    (any URL with stable content works — one on your own server is fine); or
  * lower the bar with  quorum = \"any\"  in the [canary] section; or
  * re-run with VLB_SKIP_PROBE=1 if you know this is a false alarm."
            fi
        else
            # `probe` needs the fwmark ip rules the running daemon installed.
            # If it could not run at all, that is not evidence about the
            # canary either way -- say so and carry on rather than blocking.
            warn "could not run the canary pre-flight (probe exited non-zero); continuing"
        fi
    fi
else
    FRESH_CONFIG=1
    log "no config at ${CONFIG_PATH} — installing the annotated example"
    install -d -m 0755 "$CONFIG_DIR"
    "${CURL[@]}" -o "${WORKDIR}/vlb.example.toml" \
        "https://raw.githubusercontent.com/${REPO}/${TAG}/examples/vlb.example.toml" \
        || die "could not fetch the example config"
    install -m 0644 "${WORKDIR}/vlb.example.toml" "$CONFIG_PATH"
fi

# ── install ──────────────────────────────────────────────────────────────

BACKUP=""
if [[ -x "$BIN_PATH" ]]; then
    BACKUP="${BIN_PATH}.bak"
    cp -f "$BIN_PATH" "$BACKUP"
    log "previous binary saved as ${BACKUP}"
fi

# Same directory, so the rename is atomic — a half-written binary on a
# routing gateway is a very bad outcome.
install -m 0755 "${WORKDIR}/vlb" "${BIN_PATH}.new"
mv -f "${BIN_PATH}.new" "$BIN_PATH"
ok "installed ${NEW_VERSION} to ${BIN_PATH}"

# ── systemd unit ─────────────────────────────────────────────────────────

if command -v systemctl >/dev/null; then
    if [[ ! -f "$UNIT_PATH" ]]; then
        log "installing the systemd unit"
        "${CURL[@]}" -o "${WORKDIR}/vlb.service" \
            "https://raw.githubusercontent.com/${REPO}/${TAG}/systemd/vlb.service" \
            || die "could not fetch the systemd unit"
        install -m 0644 "${WORKDIR}/vlb.service" "$UNIT_PATH"
        systemctl daemon-reload
    fi
else
    warn "systemctl not found — the binary is installed but no service was configured"
fi

# ── restart and verify ───────────────────────────────────────────────────

rollback() {
    if [[ -n "$BACKUP" && -f "$BACKUP" ]]; then
        warn "rolling back to the previous binary"
        cp -f "$BACKUP" "$BIN_PATH"
        systemctl restart "$SERVICE" 2>/dev/null || true
    fi
}

if [[ "${VLB_NO_START:-0}" == "1" ]]; then
    log "VLB_NO_START=1 — not touching the service"
elif [[ $FRESH_CONFIG -eq 1 ]]; then
    echo
    ok "vlb ${NEW_VERSION} is installed."
    warn "The service was NOT started: ${CONFIG_PATH} is the stock example and
      still points at example interfaces and gateways. Edit it first:"
    echo "    sudo \$EDITOR ${CONFIG_PATH}"
    echo "    sudo vlb --config ${CONFIG_PATH} check"
    echo "    sudo vlb --config ${CONFIG_PATH} probe      # times each health layer"
    echo "    sudo systemctl enable --now ${SERVICE}"
    exit 0
elif command -v systemctl >/dev/null; then
    if [[ $WAS_RUNNING -eq 1 ]]; then
        log "restarting ${SERVICE}"
        if ! systemctl restart "$SERVICE"; then
            rollback
            die "${SERVICE} failed to restart; rolled back. Logs: journalctl -u ${SERVICE} -n 50"
        fi
    else
        log "enabling and starting ${SERVICE}"
        systemctl enable --now "$SERVICE" || { rollback; die "could not start ${SERVICE}"; }
    fi

    # Wait for the gateway to actually be carrying traffic again, rather than
    # merely for systemd to report the process as started. A provider is only
    # selected after `success_threshold` consecutive probe rounds — six
    # seconds at the shipped defaults, longer on slow links — so a fixed
    # short sleep would report "no provider yet" on a perfectly healthy
    # update and leave the operator unsure whether something broke.
    # Both the command substitution and the test below need explicit
    # handling under `set -euo pipefail`. Immediately after a restart the
    # control socket is not listening yet, so `vlb status` exits non-zero;
    # with pipefail that propagates out of the assignment and `set -e` kills
    # the script — which looked exactly like a failed update even though the
    # service had come back fine. Likewise a bare `[[ … ]] && break` aborts
    # the script on the iterations where the condition is false.
    ACTIVE=""
    for _ in $(seq 1 30); do
        if ! systemctl is-active --quiet "$SERVICE"; then
            rollback
            die "${SERVICE} stopped after the restart; rolled back to the previous binary.
Logs: journalctl -u ${SERVICE} -n 50"
        fi
        ACTIVE=$("$BIN_PATH" --config "$CONFIG_PATH" status 2>/dev/null \
                   | grep -m1 '"active"' \
                   | sed 's/.*"active"[^:]*: *//; s/^"//; s/",\{0,1\}$//; s/,$//' \
                 || true)
        if [[ -n "$ACTIVE" && "$ACTIVE" != "null" ]]; then
            break
        fi
        sleep 1
    done

    if ! systemctl is-active --quiet "$SERVICE"; then
        rollback
        die "${SERVICE} is not running after the restart; rolled back.
Logs: journalctl -u ${SERVICE} -n 50"
    fi
    ok "${SERVICE} is active"

    if [[ -n "$ACTIVE" && "$ACTIVE" != "null" ]]; then
        ok "carrying traffic via: ${ACTIVE}"
    else
        # Not fatal: the daemon is up and will select a provider as soon as
        # one passes. But it does mean no uplink is healthy right now, which
        # the operator needs to hear rather than discover later.
        warn "the daemon is running but no provider has passed its checks in 30s.
      Investigate with:  sudo vlb --config ${CONFIG_PATH} probe"
    fi
fi

echo
ok "vlb ${CURRENT_VERSION:+${CURRENT_VERSION} → }${NEW_VERSION} installed."
echo
echo "  status:    sudo vlb --config ${CONFIG_PATH} status"
echo "  dashboard: sudo vlb --config ${CONFIG_PATH} tui        (press 'u' to update)"
echo "  probe:     sudo vlb --config ${CONFIG_PATH} probe      (times each health layer)"
echo "  logs:      sudo journalctl -u ${SERVICE} -f"
echo
echo "  From now on this box can also update itself with:  sudo vlb update"
