FROM rust:1.84-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --bin thorn

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/thorn /usr/local/bin/thorn
COPY thorn.toml /etc/thorn/thorn.toml

ENV RUST_LOG=thorn=info

ENTRYPOINT ["thorn"]
CMD ["daemon", "-f", "/etc/thorn/thorn.toml"]
