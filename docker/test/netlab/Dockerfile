# One image for every simulated network node in the test lab: the two ISP
# routers and the upstream origin server. Keeping it to a single image means
# one build, and the mode scripts can be identical everywhere.
# Ubuntu 24.04, matching the production server. It is not interchangeable
# with Debian here: 24.04 ships iptables on the nf_tables backend, a newer
# iputils, and — the one that actually bites — no `conntrack` by default.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        iputils-ping \
        dnsmasq \
        nginx \
        openssl \
        curl \
        ca-certificates \
        procps \
        tcpdump && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY isp-mode.sh   /usr/local/bin/isp-mode
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/isp-mode

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
