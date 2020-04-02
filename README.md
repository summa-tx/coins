# riemann-rs

`riemann-rs` is a set of transaction construction libraries for UTXO-based
chains. It aims to provide high-quality tooling for constructing
transactions, and to enable use in the browser via wasm bindings.

## Project Status

While this is feature-complete, and there are some tests, **this is essentially
alpha software**. There will be rough edges, and the interfaces are subject to
change.

## Project Architecture

The project is built around the `riemann-core` crate which defines high-level
traits and interfaces. Chain-specific libraries use these traits to provide
a consistent developer experience across chains.

We have provided a `rmn-btc` crate with a Bitcoin-targeted implementation. See
its documentation for usage instruction and details. We have also provided wasm
bindings to `rmn-btc` via `wasm-bindgen`.

## Getting started

If building a Rust app, use `rmn-btc` in the `./bitcoin/` directory. If
building for a browser, use `rmn-btc-wasm` in the `./bitcoin-wasm/` directory.

Once there, you can build and view the documentation using
`$ cargo rustdoc --open`.


## Building & running tests

- install [rustup](https://rustup.rs/)
- `$ cargo build`
- `$ cargo test`
- build the docs: `$ cargo rustdoc`
