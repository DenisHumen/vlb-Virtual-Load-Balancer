#!/bin/bash
# Start vlb inside the test lab.
set -uo pipefail

# Docker gives this container a default route to the host, which would let
# every probe reach the real internet and make all the fault scenarios pass
# regardless of what the simulated ISPs are doing. Remove it and let vlb
# install the only default route in this namespace — which is also the
# cleanest possible assertion that failover actually works: if vlb picks the
# wrong provider, nothing reaches the origin at all.
while ip route show default | grep -q .; do
    ip route del default || break
done
echo "[vlb-test] docker default route removed; vlb now owns the default route"

ip -brief addr show

CONFIG="${VLB_CONFIG:-/etc/vlb/vlb.toml}"

# Supervise the daemon rather than exec into it. The restart scenarios kill
# the daemon process and expect it back in the *same* network namespace —
# with the routes, rules and NAT it left behind — exactly as systemd's
# Restart=always does on a real box. Restarting the container instead would
# tear the namespace down and take every route with it; that is the reboot
# case, and it is tested separately.
child=0
forward() {
    if [ "$child" -gt 0 ]; then
        kill -TERM "$child" 2>/dev/null
        wait "$child" 2>/dev/null
    fi
    exit 0
}
trap forward TERM INT

while :; do
    /usr/local/bin/vlb --config "$CONFIG" "${@:-run}" &
    child=$!
    wait "$child"
    code=$?
    child=0
    echo "[vlb-test] vlb exited with status $code; restarting in 1s (as Restart=always would)"
    sleep 1
done
