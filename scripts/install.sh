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

set -Eeuo pipefail

REPO="${VLB_REPO:-DenisHumen/vlb-Virtual-Load-Balancer}"
BIN_PATH=/usr/local/bin/vlb
CONFIG_DIR=/etc/vlb
CONFIG_PATH="${CONFIG_DIR}/vlb.toml"
UNIT_PATH=/etc/systemd/system/vlb.service
SERVICE=vlb

C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'; C_CYN=$'\033[0;36m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=; C_GRN=; C_YLW=; C_CYN=; C_RST=; }

log()  { printf '%s[vlb]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
ok()   { printf '%s[ ok]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!! ]%s %s\n' "$C_YLW" "$C_RST" "$*"; }
die()  { printf '%s[err]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

WORKDIR=""
cleanup() { [[ -n "$WORKDIR" && -d "$WORKDIR" ]] && rm -rf "$WORKDIR"; }
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

case "$(uname -m)" in
    x86_64|amd64)  TARGET=x86_64-unknown-linux-gnu ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-gnu ;;
    *) die "no published build for $(uname -m); build from source with 'cargo build --release'" ;;
esac

log "host: $(uname -m) → ${TARGET}"

# ── locate the release ───────────────────────────────────────────────────

api() { curl -fsSL -H 'Accept: application/vnd.github+json' "$@"; }

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
curl -fsSL --retry 3 --retry-delay 2 -o "${WORKDIR}/${ASSET}" "${BASE}/${ASSET}" \
    || die "download failed: ${BASE}/${ASSET}
Check that release ${TAG} publishes an asset for ${TARGET}."

log "verifying checksum"
curl -fsSL --retry 3 -o "${WORKDIR}/${ASSET}.sha256" "${BASE}/${ASSET}.sha256" \
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
else
    FRESH_CONFIG=1
    log "no config at ${CONFIG_PATH} — installing the annotated example"
    install -d -m 0755 "$CONFIG_DIR"
    curl -fsSL -o "${WORKDIR}/vlb.example.toml" \
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
        curl -fsSL -o "${WORKDIR}/vlb.service" \
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

    # Give it a moment to bind its control port and run a first probe round.
    sleep 3
    if ! systemctl is-active --quiet "$SERVICE"; then
        rollback
        die "${SERVICE} is not running after the restart; rolled back.
Logs: journalctl -u ${SERVICE} -n 50"
    fi
    ok "${SERVICE} is active"

    # The real check: does the daemon answer, and has it chosen a provider?
    if ACTIVE=$("$BIN_PATH" --config "$CONFIG_PATH" status 2>/dev/null \
                 | grep -m1 '"active"' | sed 's/.*: *"\{0,1\}//; s/"\{0,1\},\{0,1\}$//'); then
        if [[ -n "$ACTIVE" && "$ACTIVE" != "null" ]]; then
            ok "active provider: ${ACTIVE}"
        else
            warn "the daemon is up but has not selected a provider yet — this is normal
      for the first few seconds. Watch it with: sudo vlb --config ${CONFIG_PATH} tui"
        fi
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
