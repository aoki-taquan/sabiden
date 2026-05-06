FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -s /sbin/nologin sabiden

COPY --from=builder /build/target/release/sabiden /usr/local/bin/sabiden

USER sabiden
EXPOSE 5060/udp 8080/tcp

# 設定は環境変数 or マウントされた /etc/sabiden/config.toml で
ENTRYPOINT ["/usr/local/bin/sabiden"]
CMD ["register", "--config", "/etc/sabiden/config.toml"]
