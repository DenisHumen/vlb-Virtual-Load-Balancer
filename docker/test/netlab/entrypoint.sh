#!/bin/bash
# Bring one lab node up. ROLE picks what it becomes:
#
#   origin — the "real internet": authoritative DNS for the test zone plus an
#            HTTP server holding the genuine canary content.
#   isp    — a provider router between the edge LAN and the transit network.
#            Starts in `good` mode; `isp-mode <mode>` switches its behaviour
#            at runtime, which is how the test scenarios inject faults.
set -euo pipefail

log() { printf '[%s] %s\n' "${ROLE:-node}" "$*"; }

# Find the interface holding an address in the given /24 prefix. Docker does
# NOT guarantee that networks map onto eth0/eth1 in declaration order -- in
# this lab they came out reversed, which silently put the NAT rule on the
# wrong side and made every forwarded probe fail. Deriving the names from the
# addressing is deterministic.
iface_for_subnet() {
    local prefix="$1"
    ip -o -4 addr show | awk -v p="$prefix" '$4 ~ "^"p {print $2; exit}'
}

# Docker hands every container a default route out to the host, which would
# let probes reach the real internet and quietly invalidate every scenario.
# The lab must be hermetic, so that route goes first.
drop_docker_default() {
    while ip route show default | grep -q .; do
        ip route del default || break
    done
    log "docker default route removed (lab is hermetic)"
}

case "${ROLE:?ROLE must be set}" in

origin)
    drop_docker_default

    # ── DNS for the test zone ──────────────────────────────────────────
    # Authoritative-ish: answers only what we define, refuses the rest, and
    # in particular returns NXDOMAIN for anything under .invalid — which is
    # what vlb's DNS-integrity probe expects from an honest resolver.
    cat >/etc/dnsmasq.conf <<EOF
port=53
no-resolv
no-hosts
bind-interfaces
listen-address=0.0.0.0
log-queries
address=/canary.test/${ORIGIN_IP}
address=/probe.test/${ORIGIN_IP}
EOF
    dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf &
    log "dnsmasq serving canary.test -> ${ORIGIN_IP}"

    # ── the genuine canary content ─────────────────────────────────────
    mkdir -p /var/www/origin
    cp /canary/canary.txt /var/www/origin/canary.txt
    cp /canary/throughput-64k.bin /var/www/origin/throughput-64k.bin
    cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    root /var/www/origin;

    # Mirrors the shape of the real captive-portal probe endpoints.
    location = /generate_204 { return 204; }
    location = /success.txt  { default_type text/plain; return 200 "success\n"; }
    location / { autoindex on; }
}
EOF
    nginx -g 'daemon off;' &
    log "nginx serving the genuine canary content"
    ;;

isp)
    drop_docker_default
    # /proc/sys is read-only in a normal container; compose pre-sets the knob,
    # so only complain if it is genuinely not enabled.
    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
            echo "FATAL: ip_forward is off and cannot be set" >&2
            exit 1
        fi
        log "ip_forward already enabled by the container runtime"
    fi

    EDGE_IF=$(iface_for_subnet "${EDGE_PREFIX:-10.77.0.}")
    TRANSIT_IF=$(iface_for_subnet "${TRANSIT_PREFIX:-192.0.2.}")
    if [ -z "$EDGE_IF" ] || [ -z "$TRANSIT_IF" ]; then
        echo "FATAL: could not map lab subnets onto interfaces" >&2
        ip -o -4 addr show >&2
        exit 1
    fi
    # isp-mode runs later as a separate process and needs the same mapping.
    {
        echo "EDGE_IF=$EDGE_IF"
        echo "TRANSIT_IF=$TRANSIT_IF"
        echo "PORTAL_IP=$PORTAL_IP"
    } >/run/lab-env
    export EDGE_IF TRANSIT_IF
    log "edge=$EDGE_IF transit=$TRANSIT_IF"

    # Everything leaving towards the origin is NATed, so the origin only ever
    # sees the ISP's own transit address and needs no route back into the edge
    # LAN. Same shape as a real single-armed provider.
    iptables -t nat -A POSTROUTING -o "$TRANSIT_IF" -j MASQUERADE

    # A "public" address for this ISP's interception portal. Using TEST-NET-3
    # rather than an RFC1918 address matters: vlb short-circuits a hijack that
    # resolves into private space, so a private portal would never exercise
    # the content comparison. A public-looking portal forces the real code
    # path — resolve, connect, fetch, compare bytes — which is exactly what
    # production looks like.
    ip addr add "${PORTAL_IP}/32" dev lo || true

    # The interception portal itself: what an unpaid account gets served.
    mkdir -p /var/www/portal
    cat >/var/www/portal/index.html <<EOF
<!DOCTYPE html>
<html><head><title>Service suspended</title></head>
<body><h1>${ISP_NAME}: your account is overdue</h1>
<p>Please settle your balance to restore service.</p></body></html>
EOF
    cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    root /var/www/portal;
    # Every path, whatever was asked for, gets the payment page. This is the
    # behaviour that fools reachability-only health checks.
    location / { try_files /index.html =200; }
}
EOF
    nginx -g 'daemon off;' &

    # Hijacking resolver, used only in the `expired` / `mitm` modes: answers
    # every name with the portal address.
    cat >/etc/dnsmasq.conf <<EOF
port=53
no-resolv
no-hosts
bind-interfaces
listen-address=0.0.0.0
address=/#/${PORTAL_IP}
EOF

    isp-mode "${INITIAL_MODE:-good}"
    log "ready in mode ${INITIAL_MODE:-good}"
    ;;

client)
    # An ordinary LAN host: no policy routing, no marks, no special
    # knowledge. Its only route out is the vlb box, so every assertion made
    # from here is a statement about what a real user behind the gateway
    # experiences.
    drop_docker_default
    ip route add default via "${GATEWAY_IP:?GATEWAY_IP must be set}"
    log "default route via ${GATEWAY_IP} (the vlb gateway)"
    ;;

*)
    echo "unknown ROLE '${ROLE}'" >&2
    exit 1
    ;;
esac

# Keep PID 1 alive; the services above run in the background.
log "up"
tail -f /dev/null
