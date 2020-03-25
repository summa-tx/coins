//! The `builder` module defines an abstract `TxBuilder` trait, as well as a pair of concrete
//! implementations that build Bitcoin transactions.

pub mod build;
pub mod bitcoin;

pub use build::*;
pub use bitcoin::*;
