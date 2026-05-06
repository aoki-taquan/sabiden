FROM rust:1.95-bookworm AS builder
WORKDIR /build
# libopus-dev は Opus ↔ G.711 トランスコード (Issue #25) に必要
RUN apt-get update && apt-get install -y --no-install-recommends \
    libopus-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin sabiden

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libopus0 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -s /sbin/nologin sabiden

COPY --from=builder /build/target/release/sabiden /usr/local/bin/sabiden

USER sabiden
EXPOSE 5060/udp 8080/tcp

# 設定は環境変数 or マウントされた /etc/sabiden/config.toml で
ENTRYPOINT ["/usr/local/bin/sabiden"]
CMD ["register", "--config", "/etc/sabiden/config.toml"]
