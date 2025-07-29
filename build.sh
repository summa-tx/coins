#!/bin/sh

set -e

# simple function to print on fail
fail() {
    echo ""
    echo "Build failed: $1"
    exit 1
}

cargo c -q || fail "Cargo build"
cargo test -q --workspace || fail "Cargo workspace tests"
cargo test -q --doc || fail "Cargo documentation tests"

### BIP32 ###
cargo c -q -p coins-bip32 || fail "BIP32 build failed"
cargo c -q -p coins-bip32 --no-default-features || fail "BIP32 build without default features"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo c -q -p coins-bip32 --target wasm32-unknown-unknown || fail "BIP32 wasm build "

### BIP39 ###
cargo c -q -p coins-bip39 || fail "BIP39 build"
cargo c -q -p coins-bip39 --no-default-features || fail "BIP39 build without default features"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo c -q -p coins-bip39 --target wasm32-unknown-unknown || fail "BIP39 wasm build"

### Ledger ###
# #  broken on travis
# cargo c -q
cargo c -q -p coins-ledger --target wasm32-unknown-unknown --no-default-features --features="browser" || fail "Ledger wasm build "
