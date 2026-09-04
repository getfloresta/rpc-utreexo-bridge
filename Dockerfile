FROM rust:slim-bullseye as build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bullseye-slim

WORKDIR /app

COPY --from=build /app/target/release/bridge /app/bridge

EXPOSE 8333

VOLUME /app/data
ENV DATA_DIR=/app/data

ENTRYPOINT ["/app/bridge"]
