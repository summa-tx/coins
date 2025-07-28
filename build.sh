#!/bin/sh

set -e

cargo build
cargo test --lib
cargo test --doc

### BIP32 ###
cd crates/bip32
cargo build
cargo build --no-default-features
cargo build --target wasm32-unknown-unknown

### BIP39 ###
cd ../bip39
cargo build
cargo build --no-default-features
cargo build --target wasm32-unknown-unknown

### Ledger ###
cd ../ledger
# #  broken on travis
# cargo build
cargo build --target wasm32-unknown-unknown --no-default-features --features="browser"
