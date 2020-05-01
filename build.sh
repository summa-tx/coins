#!/bin/sh

cargo build --verbose
cargo test --verbose

### BIP32 ###
cd bip32
# default features covered by workspace-level tests
cargo test --verbose --features="rust-secp" --no-default-features
cargo test --verbose --features="rust-secp, rust-secp-static-context" --no-default-features

# Build bip32 wasm
cargo build --verbose --features="rust-secp" --no-default-featuresz --target wasm32-unknown-unknown
cargo build --verbose --features="rust-secp, rust-secp-static-context" --no-default-features --target wasm32-unknown-unknown

### PSBT ###
cd ../psbt
# default features covered by workspace-level tests
cargo test --verbose --features="rust-secp" --no-default-features

# Build psbt wasm
cargo test --verbose --features="rust-secp" --no-default-features --target wasm32-unknown-unknown

### BTC_WASM ###
cd ../bitcoin-wasm
cargo build --verbose
cargo test --verbose

cargo build --verbose --target wasm32-unknown-unknown
