# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM rust:1.90-bookworm AS builder

WORKDIR /src

# Cache deps separately from source. We do a stub-build trick so cargo
# fetches and compiles the dependency graph once.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() { println!(\"stub\"); }" > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/vlb target/release/deps/vlb-* target/release/.fingerprint/vlb-*

COPY src ./src
COPY canary ./canary
COPY rustfmt.toml ./
RUN cargo build --release --locked && \
    strip target/release/vlb

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        iptables \
        conntrack \
        ca-certificates \
        tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/vlb /usr/local/bin/vlb

RUN mkdir -p /etc/vlb /var/lib/vlb

VOLUME ["/var/lib/vlb"]

ENV VLB_CONFIG=/etc/vlb/vlb.toml \
    RUST_LOG=info

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vlb"]
CMD ["run", "--config", "/etc/vlb/vlb.toml"]
