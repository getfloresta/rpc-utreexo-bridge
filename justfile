_default:
    just --list

# Check all feature combinations
check:
    cargo check
    cargo check --features esplora
    cargo check --no-default-features --features shinigami

# Build all feature combinations
build:
    cargo build --release
    cargo build --release --features esplora
    cargo build --release --no-default-features --features shinigami

# Test all feature combinations
test:
    cargo test
    cargo test --features esplora
    cargo test --no-default-features --features shinigami

# Run clippy on all feature combinations with MSRV
clippy:
    cargo +1.85.0 clippy
    cargo +1.85.0 clippy --features esplora
    cargo +1.85.0 clippy --no-default-features --features shinigami

# Run all checks
ci: check test clippy fmt-check

# Clean build artifacts
clean:
    cargo clean

# Format code
fmt:
    cargo +1.85.0 fmt

# Check if code is formatted
fmt-check:
    cargo +1.85.0 fmt --check
