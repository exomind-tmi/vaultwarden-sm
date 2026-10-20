# Build stage — same base family as vaultwarden's Debian image.
FROM docker.io/library/rust:1.99-slim-trixie AS build

# C toolchain for the bundled SQLite (libsqlite3-sys) build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --bin vaultwarden-sm

# Runtime stage.
FROM docker.io/library/debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/vaultwarden-sm /usr/local/bin/vaultwarden-sm

WORKDIR /data
ENV DATA_DIR=/data \
    ROCKET_ADDRESS=0.0.0.0 \
    ROCKET_PORT=8080
EXPOSE 8080

ENTRYPOINT ["vaultwarden-sm"]
