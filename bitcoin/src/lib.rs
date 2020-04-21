//! This crate provides a simple interface for interacting with Bitcoin mainnet,
//! testnet, and signet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

#[macro_use]
pub(crate) mod prelude;

pub mod builder;
pub mod enc;
pub mod hashes;
pub mod nets;
pub mod psbt;
pub mod types;

pub use builder::*;
pub use enc::*;
pub use hashes::*;
pub use nets::*;
pub use psbt::*;
pub use types::*;
