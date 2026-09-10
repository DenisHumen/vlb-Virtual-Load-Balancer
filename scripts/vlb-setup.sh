#!/usr/bin/env bash
# vlb setup — guided install, and a menu for a gateway that is already up.
#
#   sudo bash scripts/vlb.sh install
#
# On a machine with no configuration this walks through the whole setup:
# dependencies, which interface faces the LAN, one block per uplink, then it
# writes /etc/vlb/vlb.toml, installs the service and waits until traffic is
# actually flowing through a verified provider.
#
# On a machine that already has one it opens a menu instead: add or change an
# uplink, restart, look at who is connected, diagnose a problem, update.
#
# Two rules this script holds itself to, because both have bitten this
# deployment before:
#
#   * Never leave a configuration in place that the daemon would reject. Every
#     change is written to a temporary file, validated with the real binary,
#     and only then moved over the live one — with the previous version kept.
#   * Never leave root-owned files in the operator's checkout. Building under
#     sudo makes target/ unwritable for the ordinary user afterwards, so the
#     build is handed back to whoever owns the source tree.

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)

CONFIG_DIR=/etc/vlb
CONFIG_PATH="${CONFIG_DIR}/vlb.toml"
TEMPLATE="${REPO_DIR}/examples/vlb.example.toml"
UNIT_SRC="${REPO_DIR}/systemd/vlb.service"
UNIT_PATH=/etc/systemd/system/vlb.service
INSTALLED_BIN=/usr/local/bin/vlb
BUILT_BIN="${REPO_DIR}/target/release/vlb"
SERVICE=vlb

C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'
C_CYN=$'\033[0;36m'; C_BLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=; C_GRN=; C_YLW=; C_CYN=; C_BLD=; C_DIM=; C_RST=; }

# Everything a person reads goes to one descriptor, opened once; stdout is
# left for the handful of functions that return a value by printing it.
#
# Those functions are called inside `$( )`, and anything they say to the
# operator on the way would be captured along with the value — an interface
# named "1) eth0 … Interface [eth0]:". A separate descriptor keeps the two
# apart, and still shows the messages when the script is driven from a pipe,
# because it is stderr then.
#
# Opened once, and that matters. Writing `> /dev/stderr` per message reopens
# the file every time, and reopening a regular file with `>` truncates it: a
# run whose output was redirected to a log ended up with nothing in it but the
# last line printed.
#
# Test whether the terminal can actually be opened, rather than whether its
# permission bits look right: inside a container /dev/tty exists but opening
# it fails, and a wizard that writes its questions into a void is worse than
# one that refuses to start.
#
# Note the tests before each `exec`: a redirection that fails on `exec` ends a
# non-interactive shell there and then, with no message. Checking first turns
# "the script did nothing and exited 1" into a sentence.
if { : >/dev/tty; } 2>/dev/null && { : </dev/tty; } 2>/dev/null; then
    exec 9>/dev/tty 8</dev/tty
    TTY_MODE=terminal
elif { : <&0; } 2>/dev/null; then
    exec 9>&2 8<&0
    TTY_MODE=pipe
else
    exec 9>&2
    TTY_MODE=noinput
fi

msg()  { printf '%s\n' "$*" >&9; }
log()  { printf '%s[vlb]%s %s\n' "$C_CYN" "$C_RST" "$*" >&9; }
ok()   { printf '%s[ ok]%s %s\n' "$C_GRN" "$C_RST" "$*" >&9; }
warn() { printf '%s[!! ]%s %s\n' "$C_YLW" "$C_RST" "$*" >&9; }
head1() {
    printf '\n%s%s%s\n%s\n' "$C_BLD" "$*" "$C_RST" \
        "$(printf '─%.0s' $(seq 1 ${#1}))" >&9
}
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RST" >&9; }

# A failure has to be able to end the run from inside a `$( )`.
#
# `exit` in a command substitution ends the subshell and nothing else: the
# caller carries on with an empty value and the operator sees an error message
# followed by the script continuing as if nothing had happened. Signal the
# script itself instead. `$$` stays the script's pid inside a subshell, while
# `$BASHPID` is the current process, so the two differ exactly when we are in
# one.
VLB_PID=$$
trap 'exit 1' TERM
die() {
    printf '%s[err]%s %s\n' "$C_RED" "$C_RST" "$*" >&9
    [[ "$BASHPID" == "$VLB_PID" ]] || kill -TERM "$VLB_PID" 2>/dev/null || true
    exit 1
}

interactive() { [[ "$TTY_MODE" != noinput ]]; }

# ─────────────────────────────────────────────────────────────────────────
# Prompting
#
# Read from the terminal rather than from stdin where there is one: this
# script may be reached through a pipe, and a wizard that silently consumes
# its own input would answer its own questions.
# ─────────────────────────────────────────────────────────────────────────

# Consecutive reads that hit end-of-input. Answering every remaining question
# with its default because nobody is there is how an unattended run quietly
# configures the wrong thing.
ASK_EOF=0

# ask VAR "question" ["default"] — the answer lands in VAR.
#
# It is returned through a variable rather than by printing it, so that no
# call site has to wrap this in `$( )`. In a subshell the counter above
# resets on every question and `die` cannot end the run, and the two together
# turn a run that has no input left into an infinite loop: `ask_yes_no` gets
# an empty answer, complains, asks again, forever. That is not hypothetical —
# it is what an unattended wizard did for forty minutes.
ask() {
    local __ask_var="$1" __ask_prompt="$2" __ask_default="${3:-}" __ask_answer=""
    if [[ -n "$__ask_default" ]]; then
        printf '%s %s[%s]%s: ' "$__ask_prompt" "$C_DIM" "$__ask_default" "$C_RST" >&9
    else
        printf '%s: ' "$__ask_prompt" >&9
    fi
    if IFS= read -r __ask_answer <&8; then
        ASK_EOF=0
        # Nothing echoes a piped answer back, so a transcript would otherwise
        # be a column of questions with no replies under them.
        [[ "$TTY_MODE" == terminal ]] || printf '%s\n' "$__ask_answer" >&9
    else
        __ask_answer=""
        ASK_EOF=$((ASK_EOF + 1))
        printf '\n' >&9
        [[ -n "$__ask_default" ]] || die "no answer given and there is no sensible default — stopping rather than guessing"
        (( ASK_EOF < 3 )) || die "no more input — stopping rather than answering the rest of the questions myself"
    fi
    printf -v "$__ask_var" '%s' "${__ask_answer:-$__ask_default}"
}

ask_yes_no() {
    local __yn_prompt="$1" __yn_default="${2:-y}" __yn_answer
    while :; do
        ask __yn_answer "$__yn_prompt (y/n)" "$__yn_default"
        case "${__yn_answer,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) printf 'Please answer y or n.\n' >&9 ;;
        esac
    done
}

pause() {
    printf '\n%sPress Enter to continue…%s' "$C_DIM" "$C_RST" >&9
    IFS= read -r _ <&8 || true
}

# ─────────────────────────────────────────────────────────────────────────
# Privileges
# ─────────────────────────────────────────────────────────────────────────

# Everything this script does — writing /etc, installing packages, reading
# iptables — needs root. Re-exec through sudo rather than failing, and pass
# the handful of variables that matter explicitly: `sudo` resets the
# environment on most distributions, so relying on it to carry them through
# would work on one machine and not the next.
ensure_root() {
    [[ $EUID -eq 0 ]] && return 0
    command -v sudo >/dev/null || die "this needs root, and sudo is not installed. Run it as root."
    log "asking for administrator rights (sudo)…"
    exec sudo VLB_CONFIG="${VLB_CONFIG:-}" VLB_SERVICE="${VLB_SERVICE:-}" \
        bash "${BASH_SOURCE[0]}" "$@"
}

# Who owns the checkout — the account whose build artefacts these are.
repo_owner() { stat -c '%U' "$REPO_DIR" 2>/dev/null || echo root; }

# ─────────────────────────────────────────────────────────────────────────
# Dependencies
# ─────────────────────────────────────────────────────────────────────────

package_manager() {
    for m in apt-get dnf yum pacman apk; do
        command -v "$m" >/dev/null && { echo "$m"; return 0; }
    done
    return 1
}

install_packages() {
    local pm; pm=$(package_manager) || { warn "no known package manager; install these by hand: $*"; return 1; }
    log "installing: $*"
    case "$pm" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
                 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 ;;
        dnf|yum) "$pm" install -y -q "$@" >/dev/null 2>&1 ;;
        pacman)  pacman -Sy --noconfirm "$@" >/dev/null 2>&1 ;;
        apk)     apk add --quiet "$@" >/dev/null 2>&1 ;;
    esac
}

# The four external commands vlb shells out to, and what each one costs when
# it is missing. `conntrack` is the dangerous one: without it the flush after
# a switchover is a silent no-op, so failover looks like it worked while every
# established connection hangs until it times out.
check_dependencies() {
    head1 "Dependencies"
    local -a missing=()
    local -a pkgs=()
    command -v ip        >/dev/null || { missing+=(ip);        pkgs+=(iproute2); }
    command -v ping      >/dev/null || { missing+=(ping);      pkgs+=(iputils-ping); }
    command -v iptables  >/dev/null || { missing+=(iptables);  pkgs+=(iptables); }
    command -v conntrack >/dev/null || { missing+=(conntrack); pkgs+=(conntrack); }

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "ip, ping, iptables and conntrack are all present"
    else
        warn "missing: ${missing[*]}"
        if install_packages "${pkgs[@]}"; then
            local -a still=()
            for c in "${missing[@]}"; do command -v "$c" >/dev/null || still+=("$c"); done
            if [[ ${#still[@]} -eq 0 ]]; then
                ok "installed: ${missing[*]}"
            else
                warn "still missing after the install attempt: ${still[*]}"
                for c in "${still[@]}"; do
                    [[ "$c" == conntrack ]] && warn "  without conntrack, connections are NOT reset after a failover — they hang until they time out"
                    [[ "$c" == ip || "$c" == ping ]] && die "  ${c} is required; vlb cannot run without it"
                done
            fi
        fi
    fi

    if ! command -v systemctl >/dev/null; then
        warn "systemd is not present — the service will be run from a pid file instead"
    fi
}

# ─────────────────────────────────────────────────────────────────────────
# The network, as this machine sees it
# ─────────────────────────────────────────────────────────────────────────

default_interface() {
    ip -4 route show default 2>/dev/null \
        | awk '/^default/ { for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit } }'
}

interfaces_with_addresses() {
    ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | sort -u
}

address_of() {
    ip -4 -o addr show dev "$1" scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -1
}

cidr_of() {
    ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4}' | head -1
}

# pick_interface VAR — the chosen interface name lands in VAR.
pick_interface() {
    local __pi_var="$1"
    local default_if; default_if=$(default_interface)
    local -a candidates=()
    mapfile -t candidates < <(interfaces_with_addresses)
    [[ ${#candidates[@]} -gt 0 ]] || die "no interface has an IPv4 address — configure the network first"

    head1 "Which interface faces your LAN and the uplinks?"
    local i=1
    for c in "${candidates[@]}"; do
        printf '  %d) %-10s %s%s%s\n' "$i" "$c" "$C_DIM" "$(cidr_of "$c")" "$C_RST" >&9
        i=$((i + 1))
    done
    dim "The default route currently leaves through: ${default_if:-none}"

    local __pi_answer
    ask __pi_answer "Interface" "${default_if:-${candidates[0]}}"
    # Accept either a number from the list or a name typed out.
    if [[ "$__pi_answer" =~ ^[0-9]+$ ]] && (( __pi_answer >= 1 && __pi_answer <= ${#candidates[@]} )); then
        __pi_answer="${candidates[$((__pi_answer - 1))]}"
    fi
    ip link show "$__pi_answer" >/dev/null 2>&1 || die "there is no interface called '${__pi_answer}'"
    printf -v "$__pi_var" '%s' "$__pi_answer"
}

# Is this address usable as a next hop from here?
#
# A gateway has to sit in a directly-connected network: the kernel refuses
# `via` an address it would have to route to. Catching that here turns a
# puzzling daemon error into a sentence at the moment the address is typed.
inspect_gateway() {
    local gw="$1" iface="$2" route dev
    if [[ ! "$gw" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "not an IPv4 address"; return 1
    fi
    route=$(ip route get "$gw" 2>/dev/null | head -1) || true
    if [[ -z "$route" ]]; then
        echo "this machine has no route to it"; return 1
    fi
    if grep -q ' via ' <<<"$route"; then
        echo "not directly connected — it is reached through another router, so it cannot be a next hop"
        return 1
    fi
    dev=$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<<"$route")
    if [[ -n "$dev" && -n "$iface" && "$dev" != "$iface" ]]; then
        echo "reachable on ${dev}, not on ${iface}"
        return 2
    fi
    return 0
}

gateway_answers() {
    ping -c1 -W1 -n "$1" >/dev/null 2>&1
}

# ─────────────────────────────────────────────────────────────────────────
# Providers
#
# Held as `name|gateway|interface|priority|role` lines: simple to edit, and
# simple to turn back into TOML.
# ─────────────────────────────────────────────────────────────────────────

read_providers() {
    local cfg="$1"
    [[ -r "$cfg" ]] || return 0
    awk '
        function val(l) {
            sub(/^[^=]*=[[:space:]]*/, "", l)
            gsub(/^"|"$/, "", l)
            gsub(/[[:space:]]+$/, "", l)
            return l
        }
        function emit() {
            if (name != "") printf "%s|%s|%s|%s|%s\n", name, gw, ifc, pri, role
            name = ""; gw = ""; ifc = ""; pri = ""; role = "primary"
        }
        BEGIN { role = "primary" }
        /^[[:space:]]*\[\[providers\]\]/ { emit(); inblock = 1; next }
        /^[[:space:]]*\[/ { if (inblock) { emit(); inblock = 0 } ; next }
        inblock {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            if      (line ~ /^[[:space:]]*name[[:space:]]*=/)      name = val(line)
            else if (line ~ /^[[:space:]]*gateway[[:space:]]*=/)   gw   = val(line)
            else if (line ~ /^[[:space:]]*interface[[:space:]]*=/) ifc  = val(line)
            else if (line ~ /^[[:space:]]*priority[[:space:]]*=/)  pri  = val(line)
            else if (line ~ /^[[:space:]]*role[[:space:]]*=/)      role = val(line)
        }
        END { emit() }
    ' "$cfg"
}

show_providers() {
    local -n _list=$1
    local i=1
    printf '  %s%-3s %-16s %-16s %-10s %-6s %s%s\n' \
        "$C_BLD" "#" "name" "gateway" "interface" "prio" "role" "$C_RST" >&9
    for entry in "${_list[@]}"; do
        IFS='|' read -r n g f p r <<<"$entry"
        printf '  %-3s %-16s %-16s %-10s %-6s %s\n' "$i" "$n" "$g" "$f" "$p" "$r" >&9
        i=$((i + 1))
    done
    [[ ${#_list[@]} -eq 0 ]] && dim "  (none yet)"
    dim "  Lower priority number wins. Gaps are allowed and useful: they leave room"
    dim "  to slot an uplink in later without renumbering the others."
}

# prompt_provider VAR iface_default [name gw iface prio role]
#
# Ask for one uplink and leave `name|gateway|interface|priority|role` in VAR.
# Existing values, when given, become the defaults, so the same function
# serves both adding and editing.
prompt_provider() {
    local __pp_var="$1" iface_default="$2"
    local name="${3:-}" gw="${4:-}" iface="${5:-$iface_default}" prio="${6:-}" role="${7:-backup}"

    ask name "  Name (no spaces)" "$name"
    [[ -n "$name" ]] || die "a provider needs a name"
    name=${name// /-}

    while :; do
        ask gw "  Gateway (the ISP router's address)" "$gw"
        local problem status
        problem=$(inspect_gateway "$gw" "$iface") && status=0 || status=$?
        if [[ $status -eq 0 ]]; then
            if gateway_answers "$gw"; then
                ok "  ${gw} answers ping"
            else
                warn "  ${gw} does not answer ping — that is normal for some routers, and vlb will tell you if it is really unreachable"
            fi
            break
        fi
        warn "  ${gw}: ${problem}"
        if [[ $status -eq 2 ]]; then
            # Only a mismatch with the interface we assumed; the operator may
            # know better than we do.
            ask_yes_no "  Use it anyway?" "n" && break
        else
            ask_yes_no "  Use it anyway? (the daemon will most likely reject it)" "n" && break
        fi
    done

    ask iface "  Interface it is reached on" "$iface"
    ask prio "  Priority (lower wins)" "$prio"
    [[ "$prio" =~ ^[0-9]+$ ]] || die "priority must be a whole number"
    ask role "  Role (primary/backup)" "$role"
    [[ "$role" == primary || "$role" == backup ]] || role=backup

    printf -v "$__pp_var" '%s|%s|%s|%s|%s' "$name" "$gw" "$iface" "$prio" "$role"
}

# Names and priorities must both be unique: the priority decides the routing
# table, the firewall mark and the rule preference, so a duplicate would put
# two uplinks in the same place.
providers_are_sane() {
    local -n _l=$1
    local names="" prios=""
    for entry in "${_l[@]}"; do
        IFS='|' read -r n g f p r <<<"$entry"
        grep -qx "$n" <<<"$names" && { echo "two providers are called '${n}'"; return 1; }
        grep -qx "$p" <<<"$prios" && { echo "two providers have priority ${p}"; return 1; }
        names+="${n}"$'\n'; prios+="${p}"$'\n'
    done
    [[ ${#_l[@]} -ge 1 ]] || { echo "at least one provider is needed"; return 1; }
    return 0
}

# ─────────────────────────────────────────────────────────────────────────
# Writing the configuration
# ─────────────────────────────────────────────────────────────────────────

# Compose a config from a template plus a provider list, keeping every comment
# the template carries — the annotated defaults are most of its value.
compose_config() {
    local template="$1" lan_if="$2" lan_ip="$3" out="$4"; shift 4
    local -n _providers=$1

    # Everything up to the first provider block is kept verbatim.
    awk '/^[[:space:]]*\[\[providers\]\]/ { exit } { print }' "$template" > "$out"

    # …with the two facts about this machine filled in.
    if grep -q '^[[:space:]]*lan_interface' "$out"; then
        sed -i -E "s|^[[:space:]]*lan_interface[[:space:]]*=.*|lan_interface = \"${lan_if}\"|" "$out"
    fi
    if grep -q '^[[:space:]]*gateway_address' "$out"; then
        sed -i -E "s|^[[:space:]]*gateway_address[[:space:]]*=.*|gateway_address = \"${lan_ip}\"|" "$out"
    fi

    for entry in "${_providers[@]}"; do
        IFS='|' read -r n g f p r <<<"$entry"
        printf '\n[[providers]]\nname = "%s"\ngateway = "%s"\ninterface = "%s"\npriority = %s\nrole = "%s"\n' \
            "$n" "$g" "$f" "$p" "$r" >> "$out"
    done
}

vlb_binary() {
    if [[ -x "$INSTALLED_BIN" ]]; then echo "$INSTALLED_BIN"
    elif [[ -x "$BUILT_BIN" ]]; then echo "$BUILT_BIN"
    else return 1; fi
}

# Replace the live configuration only after the real binary has accepted the
# candidate. A gateway whose config the daemon rejects does not come back.
install_config() {
    local candidate="$1"
    local bin; bin=$(vlb_binary) || die "no vlb binary yet — build it first"

    if ! "$bin" --config "$candidate" check > /tmp/vlb-check.$$ 2>&1; then
        printf '\n' >&9
        sed 's/^/    /' /tmp/vlb-check.$$ >&9
        rm -f /tmp/vlb-check.$$
        return 1
    fi
    rm -f /tmp/vlb-check.$$

    install -d -m 0755 "$CONFIG_DIR"
    if [[ -f "$CONFIG_PATH" ]]; then
        local backup
        backup="${CONFIG_PATH}.$(date +%Y%m%d-%H%M%S).bak"
        cp -a "$CONFIG_PATH" "$backup"
        log "previous configuration kept as ${backup}"
    fi
    install -m 0644 "$candidate" "$CONFIG_PATH"
    ok "wrote ${CONFIG_PATH}"
}

# ─────────────────────────────────────────────────────────────────────────
# Building and installing
# ─────────────────────────────────────────────────────────────────────────

# Build as the account that owns the checkout, not as root.
#
# A release build under sudo leaves target/ owned by root, and the next
# ordinary `cargo build` in that tree fails with a wall of permission errors.
# It also installs a second rustup toolchain under /root that nobody asked
# for. Hand the work back to the owner where we can.
build_binary() {
    local owner; owner=$(repo_owner)

    if [[ -d "${REPO_DIR}/target" ]]; then
        local towner; towner=$(stat -c '%U' "${REPO_DIR}/target" 2>/dev/null || echo root)
        if [[ "$towner" == root && "$owner" != root ]]; then
            warn "target/ is owned by root from an earlier sudo build — returning it to ${owner}"
            chown -R "$owner" "${REPO_DIR}/target" 2>/dev/null || true
        fi
    fi

    if [[ "$owner" != root ]] && id "$owner" >/dev/null 2>&1; then
        log "building as ${owner} (the owner of this checkout)"
        if sudo -u "$owner" -H bash -lc "cd '${REPO_DIR}' && bash scripts/vlb.sh build"; then
            return 0
        fi
        warn "building as ${owner} did not work; falling back to root"
    fi
    VLB_NO_RESTART=1 bash "${SCRIPT_DIR}/vlb.sh" build
}

pidfile_daemon_running() {
    local pid_file=/run/vlb.pid
    [[ -f "$pid_file" ]] || return 1
    local pid; pid=$(cat "$pid_file" 2>/dev/null || true)
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

install_service() {
    # No systemd — a container, or a minimal image. `check_dependencies` has
    # already promised a pid-file daemon in that case, so deliver one rather
    # than printing an instruction and leaving the gateway not running.
    if ! command -v systemctl >/dev/null; then
        install -m 0755 "$BUILT_BIN" "$INSTALLED_BIN"
        ok "installed the binary as ${INSTALLED_BIN}"
        log "no systemd here — starting the daemon from a pid file instead"
        if VLB_NO_RESTART=1 VLB_CONFIG="$CONFIG_PATH" \
                bash "${SCRIPT_DIR}/vlb.sh" start >&9 2>&9 9>&- 8<&-; then
            ok "daemon started (stop it with: sudo bash scripts/vlb.sh stop)"
        else
            warn "could not start it — try:  sudo bash scripts/vlb.sh start"
        fi
        return 0
    fi

    # One daemon at a time. A pid-file daemon left running would hold the
    # control port and the new unit would never get it.
    if pidfile_daemon_running; then
        log "stopping the daemon that was started from the checkout"
        VLB_NO_RESTART=1 bash "${SCRIPT_DIR}/vlb.sh" stop >/dev/null 2>&1 || true
    fi

    install -m 0755 "$BUILT_BIN" "$INSTALLED_BIN"
    ok "installed the binary as ${INSTALLED_BIN}"

    if [[ -f "$UNIT_SRC" ]]; then
        install -m 0644 "$UNIT_SRC" "$UNIT_PATH"
        systemctl daemon-reload
        ok "installed the systemd unit"
    fi

    systemctl enable --now "$SERVICE" >/dev/null 2>&1 || systemctl restart "$SERVICE"
    ok "service enabled and started"
}

# Wait until the daemon is not merely running but has verified an uplink.
wait_until_serving() {
    local bin; bin=$(vlb_binary) || return 1
    local active="" adopted=""
    for _ in $(seq 1 40); do
        active=$("$bin" --config "$CONFIG_PATH" status 2>/dev/null \
                   | grep -m1 '"active"' | sed 's/.*: *//; s/^"//; s/",\{0,1\}$//; s/,$//') || true
        adopted=$("$bin" --config "$CONFIG_PATH" status 2>/dev/null \
                   | grep -m1 '"active_adopted"' | sed 's/.*: *//; s/,//') || true
        if [[ -n "$active" && "$active" != "null" && "$adopted" != "true" ]]; then
            ok "carrying traffic through ${active}, verified by its own checks"
            return 0
        fi
        sleep 1
    done
    if [[ -n "$active" && "$active" != "null" ]]; then
        warn "carrying traffic through ${active}, still verifying it"
        return 0
    fi
    warn "no provider has passed its checks yet — run:  sudo vlb --config ${CONFIG_PATH} probe"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────
# The wizard
# ─────────────────────────────────────────────────────────────────────────

wizard() {
    head1 "vlb setup"
    cat >&9 <<'EOF'
This sets up a failover gateway: several uplinks, one of which carries the
traffic, and an automatic switch to another the moment the active one stops
actually working.

It will ask for each uplink's gateway address — the ISP router this machine
talks to — and work the rest out for itself. Nothing is written until the
end, and nothing is written that the daemon would not accept.
EOF

    check_dependencies

    head1 "Building"
    if [[ -x "$BUILT_BIN" ]]; then
        ok "binary already built: $("$BUILT_BIN" --version)"
        if ask_yes_no "Rebuild it from the current sources?" "n"; then
            build_binary
        fi
    else
        log "building the binary (this takes a couple of minutes on a first run)"
        build_binary
    fi
    [[ -x "$BUILT_BIN" ]] || die "the build did not produce ${BUILT_BIN}"

    local lan_if lan_ip
    pick_interface lan_if
    lan_ip=$(address_of "$lan_if")
    ok "using ${lan_if} (${lan_ip:-no address})"

    head1 "Uplinks"
    cat >&9 <<'EOF'
Add them best first. The first one you enter is the primary; the others are
tried in the order you give them if it fails.
EOF
    local -a providers=()
    local n=0 suggested_name suggested_role
    while :; do
        n=$((n + 1))
        if [[ $n -eq 1 ]]; then suggested_name="isp-main"; suggested_role="primary"
        else suggested_name="isp-${n}"; suggested_role="backup"; fi

        printf '\n%sUplink %d%s\n' "$C_BLD" "$n" "$C_RST" >&9
        local entry
        prompt_provider entry "$lan_if" "$suggested_name" "" "$lan_if" "$(( (n - 1) * 1 ))" "$suggested_role"
        providers+=("$entry")

        if [[ $n -ge 2 ]]; then
            ask_yes_no $'\nAdd another uplink?' "n" || break
        else
            ask_yes_no $'\nAdd a backup uplink? (strongly recommended — with one uplink there is nothing to fail over to)' "y" || break
        fi
    done

    local problem
    problem=$(providers_are_sane providers) || die "$problem"

    head1 "Review"
    show_providers providers
    printf '\n  config      %s\n  interface   %s\n  this host   %s\n' "$CONFIG_PATH" "$lan_if" "${lan_ip:-unknown}" >&9
    ask_yes_no $'\nWrite this configuration?' "y" || die "nothing was changed"

    local candidate; candidate=$(mktemp)
    compose_config "$TEMPLATE" "$lan_if" "${lan_ip:-127.0.0.1}" "$candidate" providers
    install_config "$candidate" || { rm -f "$candidate"; die "the daemon rejected that configuration (shown above); nothing was changed"; }
    rm -f "$candidate"

    head1 "Starting"
    install_service
    wait_until_serving || true

    head1 "Done"
    local logs_cmd="sudo journalctl -u ${SERVICE} -f"
    command -v systemctl >/dev/null || logs_cmd="sudo tail -f /var/log/vlb.log"
    cat >&9 <<EOF
  Configuration   ${CONFIG_PATH}
  Dashboard       sudo vlb tui            (press c for the client list)
  Status          sudo vlb status
  Who is on it    sudo vlb clients
  Health check    sudo vlb probe
  This menu       sudo bash scripts/vlb.sh install
  Logs            ${logs_cmd}
EOF
}

# ─────────────────────────────────────────────────────────────────────────
# The menu, for a gateway that is already configured
# ─────────────────────────────────────────────────────────────────────────

# Rewrite only the provider blocks, keeping the rest of the file — including
# every local change made since the install — exactly as it is.
save_providers() {
    local -n _list=$1
    local problem
    problem=$(providers_are_sane _list) || { warn "$problem"; return 1; }

    if awk '/^[[:space:]]*\[\[providers\]\]/ { seen = 1 } seen && /^[[:space:]]*\[[^[]/ { found = 1 } END { exit !found }' "$CONFIG_PATH"; then
        warn "there is another section after [[providers]] in ${CONFIG_PATH}."
        warn "Move the provider blocks to the end of the file and try again — otherwise"
        warn "rewriting them here would drop whatever follows."
        return 1
    fi

    local candidate; candidate=$(mktemp)
    awk '/^[[:space:]]*\[\[providers\]\]/ { exit } { print }' "$CONFIG_PATH" > "$candidate"
    for entry in "${_list[@]}"; do
        IFS='|' read -r n g f p r <<<"$entry"
        printf '\n[[providers]]\nname = "%s"\ngateway = "%s"\ninterface = "%s"\npriority = %s\nrole = "%s"\n' \
            "$n" "$g" "$f" "$p" "$r" >> "$candidate"
    done

    if install_config "$candidate"; then
        rm -f "$candidate"
        if ask_yes_no "Restart now so the change takes effect?" "y"; then
            restart_daemon
            wait_until_serving || true
        else
            warn "the change is on disk but not live until you restart"
        fi
        return 0
    fi
    rm -f "$candidate"
    warn "the daemon rejected that configuration (shown above); nothing was changed"
    return 1
}

restart_daemon() {
    if command -v systemctl >/dev/null && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
        log "restarting ${SERVICE}"
        systemctl restart "$SERVICE" && ok "restarted — the route is adopted, so traffic kept flowing"
    elif pidfile_daemon_running; then
        VLB_NO_RESTART=1 bash "${SCRIPT_DIR}/vlb.sh" restart >&9 2>&9 9>&- 8<&-
    else
        warn "the daemon is not running; starting it"
        install_service
    fi
}

menu_providers() {
    local -a providers=()
    mapfile -t providers < <(read_providers "$CONFIG_PATH")
    local lan_if; lan_if=$(default_interface)

    while :; do
        head1 "Uplinks"
        show_providers providers
        cat >&9 <<'EOF'

  1) Add one
  2) Change one
  3) Remove one
  0) Back
EOF
        local choice; ask choice "Choice" "0"
        case "$choice" in
            1)
                local next_prio=0 entry
                for e in "${providers[@]}"; do
                    IFS='|' read -r _ _ _ p _ <<<"$e"
                    (( p >= next_prio )) && next_prio=$((p + 1))
                done
                printf '\n' >&9
                prompt_provider entry "$lan_if" "isp-$((${#providers[@]} + 1))" "" "$lan_if" "$next_prio" "backup"
                providers+=("$entry")
                save_providers providers || mapfile -t providers < <(read_providers "$CONFIG_PATH")
                ;;
            2)
                [[ ${#providers[@]} -gt 0 ]] || { warn "there are none yet"; continue; }
                local idx; ask idx "Which number" "1"
                [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#providers[@]} )) || { warn "no such entry"; continue; }
                IFS='|' read -r n g f p r <<<"${providers[$((idx - 1))]}"
                printf '\n' >&9
                local edited; prompt_provider edited "$lan_if" "$n" "$g" "$f" "$p" "$r"
                providers[$((idx - 1))]="$edited"
                save_providers providers || mapfile -t providers < <(read_providers "$CONFIG_PATH")
                ;;
            3)
                [[ ${#providers[@]} -gt 1 ]] || { warn "a gateway needs at least one uplink"; continue; }
                local idx; ask idx "Which number" ""
                [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#providers[@]} )) || { warn "no such entry"; continue; }
                IFS='|' read -r n _ _ _ _ <<<"${providers[$((idx - 1))]}"
                if ask_yes_no "Remove '${n}'?" "n"; then
                    providers=("${providers[@]:0:$((idx - 1))}" "${providers[@]:$idx}")
                    save_providers providers || mapfile -t providers < <(read_providers "$CONFIG_PATH")
                fi
                ;;
            0|"") return 0 ;;
            *) warn "pick 0-3" ;;
        esac
    done
}

# Keep connections on the uplink they started on.
#
# Its own menu entry rather than a line in the config for the operator to
# find, because it is the setting that decides whether a failback is felt.
# Does the build that is actually deployed know this setting?
#
# The menu validates every change with the binary that will run it, which is
# right — but when the checkout is newer than the deployed build, the answer
# comes back as a raw TOML parse error about an unknown field, and the real
# cause (an old binary, not a bad setting) is nowhere in it. Ask first.
pinning_supported() {
    local bin; bin=$(vlb_binary) || return 1
    local probe; probe=$(mktemp)
    # Inserted into the existing [routing] table rather than appended: a
    # second [routing] header is a duplicate-table error in TOML, and the
    # probe would then fail for a reason that has nothing to do with the key.
    awk '
        /^[[:space:]]*pin_connections[[:space:]]*=/ { next }
        { print }
        /^[[:space:]]*\[routing\][[:space:]]*$/ { print "pin_connections = false" }
    ' "$CONFIG_PATH" >"$probe"
    local out
    out=$("$bin" --config "$probe" check 2>&1) && { rm -f "$probe"; return 0; }
    rm -f "$probe"
    grep -q "unknown field .pin_connections" <<<"$out" && return 1
    # Some other complaint about the config entirely — not our question.
    return 0
}

menu_pinning() {
    head1 "Connections during a switch"

    if ! pinning_supported; then
        warn "the vlb running on this machine is older than this checkout and does"
        warn "not know this setting yet, so turning it on would only produce a"
        warn "configuration it refuses to load."
        msg ""
        msg "  Deploy the current sources first:"
        msg "    sudo bash scripts/vlb.sh update"
        msg ""
        if ask_yes_no "Run that now?" "y"; then
            bash "${SCRIPT_DIR}/vlb.sh" update >&9 2>&9 9>&- 8<&- \
                || warn "the update did not succeed — the reason is above"
            msg ""
            log "open this entry again once the update has finished"
        fi
        pause
        return 0
    fi

    local current="off"
    grep -qE '^[[:space:]]*pin_connections[[:space:]]*=[[:space:]]*true' "$CONFIG_PATH" \
        && current="on"

    cat >&9 <<'EOF'
When this is off, moving the default route moves every connection at once.
Coming back to the primary after it recovers, pinning a provider by hand and
the route watchdog tidying up after netplan all reset every connection on the
box — and those are most of the switches a healthy gateway makes.

When it is on, each connection stays on the uplink it started on. Only new
connections follow the new route, so those switches are not felt at all.

It cannot save a connection whose own uplink dies: that uplink's router gives
you its own public address, and the far end hangs up the moment traffic comes
from a different one. What it does there is drop that uplink's connections at
once, and leave everyone else's alone.
EOF
    msg ""
    if [[ "$current" == on ]]; then
        ok "  currently ON"
    else
        dim "  currently off"
    fi

    if ! command -v conntrack >/dev/null; then
        warn "conntrack is not installed, and this needs it to release the"
        warn "connections of an uplink that goes down. Install it first:"
        warn "  sudo apt-get install -y conntrack"
        pause
        return 0
    fi

    local want
    if [[ "$current" == on ]]; then
        ask_yes_no $'\nTurn it off?' "n" || { pause; return 0; }
        want=false
    else
        ask_yes_no $'\nTurn it on?' "y" || { pause; return 0; }
        want=true
    fi

    local candidate; candidate=$(mktemp)
    # Replace the key if it is there, add it under [routing] if it is not.
    awk -v want="$want" '
        /^[[:space:]]*pin_connections[[:space:]]*=/ { print "pin_connections = " want; seen = 1; next }
        { print }
        /^[[:space:]]*\[routing\][[:space:]]*$/ && !seen { print "pin_connections = " want; seen = 1 }
    ' "$CONFIG_PATH" > "$candidate"

    if ! grep -qE "^pin_connections = (true|false)" "$candidate"; then
        rm -f "$candidate"
        warn "could not find a [routing] section to change — edit ${CONFIG_PATH} by hand"
        pause
        return 0
    fi

    if install_config "$candidate"; then
        rm -f "$candidate"
        restart_daemon
        wait_until_serving || true
        if [[ "$want" == true ]]; then
            ok "connections now stay on the uplink they started on"
            dim "  watch the 'pinned' line in  sudo vlb tui  to see it working"
        else
            ok "connection pinning is off again"
        fi
    else
        rm -f "$candidate"
        warn "the daemon rejected that change (shown above); nothing was altered"
    fi
    pause
}

# How sure the gateway has to be before it moves everybody.
#
# Its own entry because it is the setting an operator actually reaches for,
# and because getting it wrong in either direction is felt: too eager and the
# gateway switches on a hiccup, resetting every connection on the network;
# too patient and an outage lasts longer than it needed to.
menu_sensitivity() {
    head1 "How readily it switches"

    local health dns canary tput
    health=$(config_value failure_threshold "$CONFIG_PATH" health)
    dns=$(config_value dns_failure_threshold "$CONFIG_PATH" health)
    canary=$(config_value failure_threshold "$CONFIG_PATH" canary)
    tput=$(config_value failure_threshold "$CONFIG_PATH" canary.throughput)
    local interval; interval=$(config_value interval_secs "$CONFIG_PATH" health)
    [[ -n "$interval" ]] || interval=3

    cat >&9 <<'EOF'
A switch is not free: it resets every connection on the network. So the
question is how long an uplink must be continuously broken before everybody
is moved off it.

Reachability is checked every few seconds; DNS, the content canary and the
throughput floor each get their own count, because a lost UDP query and a
forged payment page are not the same kind of evidence.
EOF
    msg ""
    msg "  now: reachability ${health:-?} rounds (~$(( ${health:-2} * interval ))s) · DNS ${dns:-unset} · canary ${canary:-?} · throughput ${tput:-?}"
    msg ""
    cat >&9 <<'EOF'
  1) Quick      6s   switch fast, accept that a hiccup can cost connections
  2) Balanced   12s  the shipped default — a hiccup is ignored, an outage is not
  3) Patient    30s  for lossy links, or when a reset is worse than a stall
  0) Leave it as it is
EOF

    local choice; ask choice "Choice" "0"
    local h d c t
    case "$choice" in
        1) h=2; d=2; c=2; t=2 ;;
        2) h=4; d=4; c=3; t=3 ;;
        3) h=10; d=10; c=5; t=4 ;;
        *) return 0 ;;
    esac

    local candidate; candidate=$(mktemp)
    set_config_value "$CONFIG_PATH" health failure_threshold "$h" > "$candidate"
    set_config_value "$candidate" health dns_failure_threshold "$d" > "${candidate}.2" \
        && mv "${candidate}.2" "$candidate"
    set_config_value "$candidate" canary failure_threshold "$c" > "${candidate}.2" \
        && mv "${candidate}.2" "$candidate"
    set_config_value "$candidate" canary.throughput failure_threshold "$t" > "${candidate}.2" \
        && mv "${candidate}.2" "$candidate"

    if install_config "$candidate"; then
        rm -f "$candidate"
        restart_daemon
        wait_until_serving || true
        ok "an uplink now has to be broken for about $(( h * interval ))s before anyone is moved"
    else
        rm -f "$candidate"
        warn "the daemon rejected that change (shown above); nothing was altered"
    fi
    pause
}

# Read one key out of one TOML table. Tables are flat here, so "the next
# occurrence after the header, before the next header" is the whole grammar
# that is needed.
config_value() {
    local key="$1" file="$2" table="$3"
    awk -v key="$key" -v table="[$table]" '
        $0 ~ /^[[:space:]]*\[/ { in_table = ($0 ~ "^[[:space:]]*\\" table "[[:space:]]*$") }
        in_table && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/[[:space:]]/, "")
            print; exit
        }
    ' "$file"
}

# Set one key in one TOML table, adding it if it is not there. Prints the
# whole file; the caller decides what to do with it.
set_config_value() {
    local file="$1" table="$2" key="$3" value="$4"
    awk -v key="$key" -v value="$value" -v table="[$table]" '
        function flush_pending() {
            if (in_table && !done) { print key " = " value; done = 1 }
        }
        $0 ~ /^[[:space:]]*\[/ {
            flush_pending()
            in_table = ($0 ~ "^[[:space:]]*\\" table "[[:space:]]*$")
            print; next
        }
        in_table && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            print key " = " value; done = 1; next
        }
        { print }
        END { flush_pending() }
    ' "$file"
}

menu_diagnose() {
    local bin; bin=$(vlb_binary) || { warn "no binary"; return; }
    while :; do
        head1 "Diagnostics"
        cat >&9 <<'EOF'
  1) Health of every uplink, timed  (probe)
  2) Configuration and dependencies (check)
  3) Routes and policy rules as the kernel has them
  4) Recent log
  5) Is the daemon actually running?
  0) Back
EOF
        local choice; ask choice "Choice" "0"
        case "$choice" in
            1) "$bin" --config "$CONFIG_PATH" probe || true; pause ;;
            2) "$bin" --config "$CONFIG_PATH" check || true; pause ;;
            3)
                head1 "Default routes"; ip -4 route show default >&9
                head1 "Policy rules";   ip -4 rule show >&9
                head1 "Per-provider tables"
                for t in $(ip -4 rule show | sed -n 's/.*lookup \([0-9]\+\).*/\1/p' | sort -u); do
                    printf '%stable %s%s\n' "$C_DIM" "$t" "$C_RST" >&9; ip -4 route show table "$t" >&9 || true
                done
                pause ;;
            4)
                if command -v journalctl >/dev/null && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
                    journalctl -u "$SERVICE" -n 40 --no-pager || true
                else
                    tail -40 /var/log/vlb.log 2>/dev/null || warn "no log file at /var/log/vlb.log"
                fi
                pause ;;
            5)
                if command -v systemctl >/dev/null && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
                    ok "systemd says ${SERVICE} is active"
                    systemctl status "$SERVICE" --no-pager -n 5 || true
                elif pidfile_daemon_running; then
                    ok "a daemon from the checkout is running (pid $(cat /run/vlb.pid))"
                else
                    warn "no daemon is running"
                fi
                pgrep -a vlb || true
                pause ;;
            0|"") return 0 ;;
            *) warn "pick 0-5" ;;
        esac
    done
}

menu_update() {
    head1 "Update"
    # One implementation, in vlb.sh, so the menu and the command line cannot
    # drift apart on the one operation that has to be able to go back. This
    # used to pull, rebuild and restart with no rollback of any kind.
    bash "${SCRIPT_DIR}/vlb.sh" update >&9 2>&9 9>&- 8<&-         || warn "the update did not succeed — the reason is above"

    # A stock unit gains fixes too; a hand-edited one is left alone.
    if [[ -f "$UNIT_SRC" && -f "$UNIT_PATH" ]] && ! cmp -s "$UNIT_SRC" "$UNIT_PATH"; then
        if ask_yes_no "The bundled systemd unit differs from the installed one. Replace it?" "y"; then
            cp -a "$UNIT_PATH" "${UNIT_PATH}.bak"
            install -m 0644 "$UNIT_SRC" "$UNIT_PATH"
            systemctl daemon-reload
            ok "unit updated (previous kept as ${UNIT_PATH}.bak)"
            restart_daemon
        fi
    fi
    pause
}

main_menu() {
    local bin; bin=$(vlb_binary || echo "$BUILT_BIN")
    while :; do
        head1 "vlb"
        local state="not running"
        if command -v systemctl >/dev/null && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
            state="running (systemd)"
        elif pidfile_daemon_running; then
            state="running (from the checkout)"
        fi
        local active=""
        [[ -x "$bin" ]] && active=$("$bin" --config "$CONFIG_PATH" status 2>/dev/null \
            | grep -m1 '"active"' | sed 's/.*: *//; s/^"//; s/",\{0,1\}$//; s/,$//') || true
        printf '  config   %s\n  daemon   %s\n  active   %s\n' \
            "$CONFIG_PATH" "$state" "${active:-—}" >&9
        cat >&9 <<'EOF'

  1) Status
  2) Dashboard (TUI)
  3) Who is connected (clients)
  4) Uplinks — add, change, remove
  5) Restart
  6) Diagnose a problem
  7) Update from git
  8) Connections during a switch
  9) How readily it switches
  0) Quit
EOF
        local choice; ask choice "Choice" "0"
        case "$choice" in
            1) "$bin" --config "$CONFIG_PATH" status || true; pause ;;
            2) "$bin" --config "$CONFIG_PATH" tui || true ;;
            3) "$bin" --config "$CONFIG_PATH" clients || true; pause ;;
            4) menu_providers ;;
            5) restart_daemon; wait_until_serving || true; pause ;;
            6) menu_diagnose ;;
            7) menu_update ;;
            8) menu_pinning ;;
            9) menu_sensitivity ;;
            0|q|"") printf '\n' >&9; return 0 ;;
            *) warn "pick 0-9" ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────

main() {
    ensure_root "$@"
    interactive || die "this is interactive and needs a terminal. Run it directly:  sudo bash scripts/vlb.sh install"

    case "${1:-}" in
        --menu)   [[ -f "$CONFIG_PATH" ]] || die "nothing is configured yet — run without --menu"; main_menu ;;
        --wizard) wizard ;;
        "")
            if [[ -f "$CONFIG_PATH" ]]; then
                log "found an existing configuration at ${CONFIG_PATH}"
                if ask_yes_no "Open the menu? (answering no starts the setup from scratch)" "y"; then
                    main_menu
                else
                    wizard
                fi
            else
                wizard
            fi
            ;;
        *) die "unknown option '${1}'. Use --wizard or --menu, or no argument at all." ;;
    esac
}

main "$@"
