//! The `builder` module defines an abstract `TxBuilder` trait (in `build.rs`), as well as a pair
//! of concrete implementations that build Bitcoin transactions (in `bitcoin.rs`);

pub mod build;

pub use build::*;
