#!/bin/bash
# Start vlb inside the test lab.
set -euo pipefail

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
exec /usr/local/bin/vlb --config /etc/vlb/vlb.toml "${@:-run}"
