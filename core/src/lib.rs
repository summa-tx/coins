//! `riemann-core` is an abstract description of UTXO transactions. It provides a collection of
//! traits that provide consistent interfaces to UTXO transaction construction. Riemann's traits
//! ensure that types are consistent across all steps in the tx construction process, and allow
//! for code reuse when building transactions on multiple chains (e.g. Bitcoin Mainnet and Bitcoin
//! Testnet).
//!
//! Many concepts familiar to UTXO chain developers have been genericized. Transactions are
//! modeled as a collection of `Input`s and `Output`s. Rather than addresses or scripts, the
//! `Output` trait has an associated `RecipientIdentifier`. Similarly, rather than an outpoint,
//! the `Input` trait has an associated `TXOIdentfier`.
//!
//! Support for other chains may be added by implementing these traits. We have provided an
//! implementation suitable for Bitcoin chains (mainnet, testnet, and signet) in the
//! `riemann_bitcoin` crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

pub mod builder;
pub mod enc;
pub mod hashes;
pub mod nets;
pub mod ser;
pub mod types;

pub use builder::*;
pub use enc::*;
pub use hashes::*;
pub use nets::*;
pub use ser::*;
pub use types::*;
