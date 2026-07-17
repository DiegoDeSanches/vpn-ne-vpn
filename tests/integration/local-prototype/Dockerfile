FROM rust:1.78-bookworm AS builder

WORKDIR /source
COPY crates/gateway-daemon crates/gateway-daemon
COPY tests/integration/local-prototype tests/integration/local-prototype
RUN cargo test --locked --manifest-path tests/integration/local-prototype/Cargo.toml
RUN cargo build --locked --release --manifest-path tests/integration/local-prototype/Cargo.toml

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates gosu openssl tor \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/tor-client \
    && chown debian-tor:debian-tor /var/lib/tor-client

COPY --from=builder /source/tests/integration/local-prototype/target/release/onionroute-local-prototype /usr/local/bin/onionroute-local-prototype
COPY tests/integration/local-prototype/entrypoint.sh /usr/local/bin/local-prototype-entrypoint
COPY tests/integration/local-prototype/torrc.onion-service /etc/tor/torrc.onionroute-service
COPY tests/integration/local-prototype/torrc.client /etc/tor/torrc.onionroute-client

RUN chmod 0755 /usr/local/bin/local-prototype-entrypoint
ENTRYPOINT ["/usr/local/bin/local-prototype-entrypoint"]
