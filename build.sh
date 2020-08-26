#!/bin/sh

cargo build --verbose && \
cargo test --verbose --lib && \

### BIP32 ###
cd bip32 && \
cargo --verbose build && \
cargo --verbose build --target wasm32-unknown-unknown && \

# default features covered by workspace-level tests
cargo test --verbose && \

### Provider ###
cd ../provider && \
cargo --verbose build && \
cargo --verbose build --no-default-features --features="mainnet" && \
cargo build --target wasm32-unknown-unknown && \

### PSBT ###
cd ../psbt && \
cargo --verbose build && \
cargo --verbose build --target wasm32-unknown-unknown && \

### BTC_WASM ###
cd ../bitcoins-wasm && \
cargo build --verbose && \
cargo test --verbose --lib && \

cargo build --verbose --target wasm32-unknown-unknown && \

### LEDGER ###
cd ../ledger && \
# #  broken on travis
# cargo build --verbose && \
cargo build --verbose --target wasm32-unknown-unknown --no-default-features --features="browser" && \

### HANDSHAKE ###
cd ../handshakes && \
cargo build --verbose && \
cargo test --verbose --lib
