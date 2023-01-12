#!/bin/sh

set -e

cargo build --verbose
cargo test --verbose --lib

### BIP32 ###
cd bip32
cargo --verbose build
cargo --verbose build --no-default-features
cargo --verbose build --target wasm32-unknown-unknown

### BIP39 ###
cd ../bip39
cargo --verbose build
cargo --verbose build --no-default-features
cargo --verbose build --target wasm32-unknown-unknown

### Ledger ###
cd ../ledger
# #  broken on travis
# cargo build --verbose
cargo build --verbose --target wasm32-unknown-unknown --no-default-features --features="browser"
