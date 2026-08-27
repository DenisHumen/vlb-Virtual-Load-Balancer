# syntax=docker/dockerfile:1.7
#
# vlb built from the working tree, for the failover test lab. Separate from
# docker/Dockerfile because this one also carries the test entrypoint and
# does not strip the binary (readable backtraces are worth more than size
# when a scenario fails).

FROM rust:1.90-bookworm AS builder
WORKDIR /src

# Warm the dependency cache before the source is copied, so editing a .rs
# file does not rebuild the whole graph on every test run.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/vlb target/release/deps/vlb-* target/release/.fingerprint/vlb-*

COPY src ./src
COPY canary ./canary
COPY rustfmt.toml ./
RUN cargo build --release --locked

# The production target. Notably this image does NOT preinstall conntrack:
# a stock Ubuntu 24.04 server does not have it either, and the lab should
# reproduce that rather than paper over it.
FROM ubuntu:24.04 AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        iptables \
        conntrack \
        procps \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/vlb /usr/local/bin/vlb
COPY docker/test/vlb/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /etc/vlb /var/lib/vlb

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
