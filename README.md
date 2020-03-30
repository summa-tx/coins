# riemann-rs

`riemann-rs` is a set of transaction construction libraries for UTXO-based
chains. It aims to provide high-quality Rust tooling for constructing
transactions, and to enable wasm bindings for use in the browser.

The project is built around the `riemann-core` crate which defines high-level
traits and interfaces. Chain-specific libraries use these traits to provide
a consistent developer experience across chains.

We have provided a `riemann_bitcoin` crate with a Bitcoin-targeted
implementation. See its documentation for usage instruction and details.

## Building & running tests

- install [rustup](https://rustup.rs/)
- `$ cargo build`
- `$ cargo test`
