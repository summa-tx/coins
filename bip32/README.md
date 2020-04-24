# rmn-bip32

This is an implementation of
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki). It
supports swappable backends, and has built-in backends for `libsecp256k1` and a
pure Rust implementation of the secp256k1 signature scheme.

It can be used to build wallets and applications for Bitcoin and Ethereum.

## Feature flags:

The default backend is gated by the `libsecp` feature, which is default. In
order to compile with the pure rust backend, use the `rust-secp` feature. You
may also use the optional static context for the `rust-secp` backend via the
`rust-secp-static-context` feature. Using the static context increases
compilation time and library size, but eliminates the overhead on the
first call to `Secp256k1::init()`.

Note that `libsecp` and `rust_secp` are mutually exclusive. The library will
fail to compile if both are selected.

## Building

```
$ cargo build
```

Run tests (make sure to run with all feature combinations):
```
$ cargo test
$ cargo test --features="rust-secp" --no-default-features
$ cargo test --features="rust-secp, rust-secp-static-context" --no-default-features
```

Run bench marks
```
$ cargo bench
$ cargo bench --features="rust-secp" --no-default-features
$ cargo bench --features="rust-secp, rust-secp-static-context" --no-default-features
```
