//! This crate provides a simple interface for interacting with Handshake mainnet,
//! testnet, and regtest.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

#[macro_use]
#[doc(hidden)]
#[cfg_attr(tarpaulin, skip)]
pub mod prelude;

//pub mod builder;
//pub mod enc;
//pub mod hashes;
//pub mod nets;
pub mod types;

//pub use nets::*;
