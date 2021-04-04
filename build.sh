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

### Bitcoins ###
cd ../bitcoins
cargo --verbose build --target wasm32-unknown-unknown

# default features covered by workspace-level tests
cargo test --verbose

### Provider ###
cd ../provider
cargo --verbose build
cargo --verbose build --no-default-features --features="mainnet"
cargo build --target wasm32-unknown-unknown

### PSBT ###
cd ../psbt
cargo --verbose build
cargo --verbose build --target wasm32-unknown-unknown

### Ledger ###
cd ../ledger
# #  broken on travis
# cargo build --verbose
cargo build --verbose --target wasm32-unknown-unknown --no-default-features --features="browser"

### Ledger bitcoins ###
cd ../ledger-btc
# #  broken on travis
# cargo build --verbose
cargo build --verbose --target wasm32-unknown-unknown --no-default-features --features="browser"

### HANDSHAKE ###
cd ../handshakes
cargo build --verbose
cargo test --verbose --lib
cargo --verbose build --target wasm32-unknown-unknown
