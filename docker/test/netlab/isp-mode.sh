#!/bin/bash
# Switch an ISP node between failure modes at runtime.
#
# Each mode reproduces one way a real provider breaks. They are ordered here
# roughly by how hard they are to detect:
#
#   good        everything works
#   dead        the router itself is gone (cable pulled, power cut)
#   blackhole   the router answers pings but forwards nothing
#   lossy       heavy packet loss, the classic "is it down or not" case
#   dns-blocked ICMP fine, UDP/53 dropped
#   portal-http a transparent HTTP proxy, with DNS left completely honest.
#               Every earlier layer -- including the DNS-integrity probe --
#               passes, so ONLY the content canary can detect this one. It
#               exists to prove the canary carries its own weight rather than
#               riding on the DNS check.
#   expired     THE case this project exists for: account unpaid, so DNS is
#               hijacked to the ISP's portal and every HTTP request is
#               answered with a payment page. Reachability probes all pass.
#   mitm        as `expired`, plus TLS interception with a forged certificate
set -euo pipefail

MODE="${1:?usage: isp-mode <good|dead|blackhole|lossy|dns-blocked|expired|mitm>}"
# The entrypoint already resolved which interface is which by subnet,
# because docker's ethN ordering is not guaranteed. Reuse that mapping rather
# than guessing it a second time.
# shellcheck disable=SC1091
[ -r /run/lab-env ] && . /run/lab-env
EDGE_IF="${EDGE_IF:-eth0}"
TRANSIT_IF="${TRANSIT_IF:-eth1}"
PORTAL_IP="${PORTAL_IP:-203.0.113.2}"

reset_rules() {
    iptables -F INPUT
    iptables -F FORWARD
    iptables -t nat -F PREROUTING
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    # The MASQUERADE rule in POSTROUTING is structural, not part of a mode,
    # so it is re-created rather than flushed away.
    iptables -t nat -F POSTROUTING
    iptables -t nat -A POSTROUTING -o "$TRANSIT_IF" -j MASQUERADE
    # Drop any tc qdisc left over from `lossy`.
    tc qdisc del dev "$TRANSIT_IF" root 2>/dev/null || true
    pkill -x dnsmasq 2>/dev/null || true
}

start_hijack_dns() {
    # Answer every name with the portal address, and intercept UDP/53 so it
    # does not matter which resolver the client thinks it is talking to.
    dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf &
    iptables -t nat -A PREROUTING -i "$EDGE_IF" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A PREROUTING -i "$EDGE_IF" -p tcp --dport 53 -j REDIRECT --to-ports 53
}

start_hijack_http() {
    # Every HTTP request, to any destination, gets the payment page.
    iptables -t nat -A PREROUTING -i "$EDGE_IF" -p tcp --dport 80 -j REDIRECT --to-ports 80
}

reset_rules

case "$MODE" in
good)
    ;;

dead)
    # The router is simply not there any more. Even the next-hop ping fails.
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    ;;

blackhole)
    # Answers ICMP addressed to itself, forwards nothing. This is the mode
    # that defeats a naive "ping the gateway" health check.
    iptables -P FORWARD DROP
    ;;

lossy)
    # 60% loss: enough that a single-packet probe is a coin flip, which is
    # why the ICMP probe sends a burst and requires a majority of replies.
    tc qdisc add dev "$TRANSIT_IF" root netem loss 60% 2>/dev/null || true
    ;;

dns-blocked)
    # ICMP still works end to end, UDP/53 silently disappears.
    iptables -A FORWARD -p udp --dport 53 -j DROP
    iptables -A FORWARD -p tcp --dport 53 -j DROP
    ;;

portal-http)
    # A transparent HTTP proxy and nothing else: DNS answers honestly, ICMP
    # works, UDP/53 is untouched, so the resolver still returns NXDOMAIN for
    # .invalid and the integrity probe is satisfied. The only observable
    # difference anywhere is the bytes coming back over TCP/80.
    start_hijack_http
    ;;

expired)
    # Unpaid account. DNS is hijacked to the portal, HTTP is answered by the
    # portal, HTTPS is dropped (it cannot be usefully forged without a
    # trusted certificate, so providers typically just block it). ICMP is
    # deliberately left working — that is what makes this mode invisible to
    # reachability-only checks.
    start_hijack_dns
    start_hijack_http
    iptables -A FORWARD -p tcp --dport 443 -j DROP
    ;;

mitm)
    # As `expired`, but TLS is intercepted with a self-signed certificate
    # instead of being dropped, so the TLS path is exercised too: the
    # handshake must fail certificate validation rather than succeed.
    start_hijack_dns
    start_hijack_http
    if [ ! -f /etc/ssl/private/portal.key ]; then
        mkdir -p /etc/ssl/private
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout /etc/ssl/private/portal.key \
            -out /etc/ssl/private/portal.crt \
            -days 3 -subj "/CN=*" >/dev/null 2>&1
    fi
    cat >/etc/nginx/conf.d/portal-tls.conf <<'EOF'
server {
    listen 443 ssl default_server;
    ssl_certificate     /etc/ssl/certificate.crt;
    ssl_certificate_key /etc/ssl/private/portal.key;
    root /var/www/portal;
    location / { try_files /index.html =200; }
}
EOF
    cp /etc/ssl/private/portal.crt /etc/ssl/certificate.crt
    nginx -s reload 2>/dev/null || true
    iptables -t nat -A PREROUTING -i "$EDGE_IF" -p tcp --dport 443 -j REDIRECT --to-ports 443
    ;;

*)
    echo "unknown mode '$MODE'" >&2
    exit 1
    ;;
esac

echo "$MODE" >/run/isp-mode
echo "mode = $MODE"
