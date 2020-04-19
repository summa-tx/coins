//! This crate provides a basic implementation of BIP32 and related BIPs.

#![forbid(unsafe_code)]

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

// /// Keys and related functionality
// pub mod keys;
//
/// Extended keys and related functionality
pub mod xkeys;

// /// Network-differentiated encoders for xkeys
// pub mod enc;

/// The curve-math backend, selected at compile time. Defaults to native libsecp256k1 bindings.
pub mod backend;

use secp256k1;
use thiserror::{Error};

/// Errors for this library
#[derive(Debug, Error)]
pub enum Bip32Error {
    /// Error bubbled up froom secp256k1
    #[error(transparent)]
    Secp256k1Error(#[from] secp256k1::Error),

    /// Master key seed generation received <16 bytes
    #[error("Master key seed generation received <16 bytes")]
    SeedTooShort,

    /// HMAC I_l was invalid during key generations.
    #[error("HMAC left segment was 0 or greated than the curve order. How?")]
    InvalidKey,

    /// Attempted to derive the child of a hardened xpub
    #[error("Attempted to derive the child of a hardened xpub")]
    HardenedKey,

    /// Attempted to tweak an xpriv or xpub directly
    #[error("Attempted to tweak an xpriv or xpub directly")]
    BadTweak
}
