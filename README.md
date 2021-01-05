# coins & bitcoins

[![Coverage Status](https://coveralls.io/repos/github/summa-tx/riemann-rs/badge.svg?branch=master)](https://coveralls.io/github/summa-tx/riemann-rs?branch=master)

`coins` is a set of transaction construction libraries for UTXO-based
chains. It aims to provide high-quality tooling for constructing
transactions, and to enable use in the browser via `wasm-bindgen`.


## Building & running tests

- install [rustup](https://rustup.rs/)
- Run _all_ the tests `$ ./build.sh`
- build the docs: `$ cargo rustdoc`

## Project Goals

- Easy to use Bitcoin tooling
- Generic traits supporting multiple networks
- WASM compatibility in all packages
- Support essential BIPs

## Project Architecture

The project is built around the `coins-core` crate which defines high-level
traits and interfaces. Chain-specific libraries use these traits to provide
a consistent developer experience across chains.

We have provided a `bitcoins` crate with a Bitcoin-targeted implementation. See
its documentation for usage instruction and details.

Other than that:
- `coins-bip32` provides tooling for BIP32 HDKey derivation
- `bitcoins-psbt` (WIP) implements the BIP174 partially-signed transaction
    format.
- `bitcoins-provider` gives a simple consistent interface to chain data with
swappable backends.

## Project Status

While this is feature-complete, and there are some tests, **much of it is
alpha software**. There will be rough edges, and the interfaces are subject to
change.

Specificallly:
- `core`, `bip32`, and `bitcoins` are relatively stable.
- `provider` is working, but does not yet have a stable API
- `psbt`, `ledger`, and `ledger-btc` are essentially alpha

# License Notes

Some work in the `ledger` crate is reproduced under the APACHE 2.0 license. See
the readme for documentation
