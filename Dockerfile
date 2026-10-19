FROM rust:1.89.0-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake pkg-config libboost-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.* ./
COPY src ./src
RUN (test -f Cargo.lock || cargo generate-lockfile) && cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/target/release/bridge /app/bridge

EXPOSE 8333

VOLUME /app/data
ENV DATA_DIR=/app/data

ENTRYPOINT ["/app/bridge"]
