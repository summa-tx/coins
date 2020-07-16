# coins & bitcoins

[![Coverage Status](https://coveralls.io/repos/github/summa-tx/riemann-rs/badge.svg?branch=master)](https://coveralls.io/github/summa-tx/riemann-rs?branch=master)

`coins` is a set of transaction construction libraries for UTXO-based
chains. It aims to provide high-quality tooling for constructing
transactions, and to enable use in the browser via `wasm-bindgen`.

## Building & running tests

- install [rustup](https://rustup.rs/)
- Run _all_ the tests `$ ./build.sh`
- build the docs: `$ cargo rustdoc`

## Project Architecture

The project is built around the `coins-core` crate which defines high-level
traits and interfaces. Chain-specific libraries use these traits to provide
a consistent developer experience across chains.

We have provided a `bitcoins` crate with a Bitcoin-targeted implementation. See
its documentation for usage instruction and details. We have also provided wasm
bindings to `bitcoins` via `wasm-bindgen`.

- `bitcoins-bip32` provides tooling for BIP32 HDKey derivation
- `bitcoins-psbt` implements the BIP174 partially-signed transaction format.
- `bitcoins-provider` gives a simple consistent interface to chain data with
swappable backends.

## Getting started

If building a Rust app, use `bitcoins` in the `./bitcoins/` directory. If
building for a browser, use `bitcoins-wasm` in the `./bitcoins-wasm/` directory.

Once there, you can build and view the documentation using
`$ cargo rustdoc --open`.

## Project Status

While this is feature-complete, and there are some tests, **much of it is
alpha software**. There will be rough edges, and the interfaces are subject to
change.

Specificallly:
- `core` and `bitcoins` are relatively stable.
- `bitcoins-wasm` is usable, but some `bitcoin` functionality is not yet
exposed.
- `provider` is working, but does not yet have thorough integration testing
- `bip32`
  - wasm features are awaiting parity secp version bump.
  - libsecp (default) features are RC1.
  - the backends will eventually be broken into a separate module.
- `psbt` is early alpha.

# License Notes

Some work in the `ledger` crate is reproduced under the APACHE 2.0 license. See
the readme for documentation
