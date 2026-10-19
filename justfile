_default:
    just --list

# Check supported backends
check:
    cargo check
    cargo check --features esplora

# Build supported backends
build:
    cargo build --release
    cargo build --release --features esplora

# Test supported backends
test:
    cargo test
    cargo test --features esplora

# Run clippy for supported backends with the MSRV
clippy:
    cargo +1.89.0 clippy
    cargo +1.89.0 clippy --features esplora

# Run all checks
ci: check test clippy fmt-check

# Clean build artifacts
clean:
    cargo clean

# Format code
fmt:
    cargo fmt

# Check if code is formatted
fmt-check:
    cargo fmt --check
