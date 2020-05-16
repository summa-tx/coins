# rmn-bip32

This is an implementation of
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki). It
supports swappable backends, and has built-in backends for `libsecp256k1` and a
pure Rust implementation of the secp256k1 signature scheme.

It can be used to build wallets and applications for Bitcoin and Ethereum.

## Backends

All key types are `Generic` types with swappable backends. The crate comes with
1 compiled-in backend. For non-wasm architectures the backend wraps native
bindings to Pieter Wuille's libsecp256k1. For wasm, it wraps Parity's pure rust
secp256k1 implementation.

## Building

```
$ cargo build
$ cargo build --target wasm32-unknown-unknown
```

Run tests (make sure to run with all feature combinations):
```
$ cargo test
```

Run bench marks
```
$ cargo bench
$ cargo bench --no-default-features
```
