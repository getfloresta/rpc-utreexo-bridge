FROM rust:1.85.0-slim-bullseye as build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bullseye-slim

WORKDIR /app

COPY --from=build /app/target/release/bridge /app/bridge

EXPOSE 8000
EXPOSE 9000

VOLUME /app/data

ENV DATA_DIR=/app/data

CMD ["/app/bridge"]
