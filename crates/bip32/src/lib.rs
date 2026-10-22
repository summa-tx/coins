#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations,
    unreachable_pub,
    unused_crate_dependencies,
    clippy::missing_const_for_fn,
    unused_extern_crates
)]

//! This crate provides a basic implementation of BIP32, BIP49, and BIP84.
//!
//! Keys carry their network. Root keys default to Bitcoin mainnet; call `set_network` to change
//! it. Parse with `str::parse` or `XPriv::from_base58`, which accept Bitcoin mainnet and testnet
//! prefixes and remember which one they saw; serialize with `to_base58`. Any other network is a
//! `NetworkVersions` constant passed to `from_base58_with`, `set_network`, or the `deserialize_*`
//! helpers in `enc`. The `prelude` module exports everything needed to get started.
//!
//! # Warnings:
//!
//! - This crate is NOT designed to be used in adversarial environments.
//! - This crate has NOT had a comprehensive security review.
//!
//! # Usage
//! ```
//! use coins_bip32::prelude::*;
//! use coins_core::hashes::{Digest, Hash256};
//!
//! # fn main() -> Result<(), Bip32Error> {
//! let msg = b"hello world";
//!
//! let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
//!
//! let xpriv: XPriv = xpriv_str.parse()?;
//!
//! let child_xpriv = xpriv.derive_child(33)?;
//! let (sig, _recovery_id): (Signature, RecoveryId) =
//!     child_xpriv.sign_digest(|d: &mut Hash256| d.update(msg));
//!
//! // Signing key types are associated with verifying key types. You can always derive a pubkey
//! let child_xpub = child_xpriv.verify_key();
//! child_xpub.verify_digest(|d: &mut Hash256| Ok(d.update(msg)), &sig)?;
//!
//! // Or sign and verify a pre-filled hasher
//! let digest = Hash256::new_with_prefix(msg);
//! let sig = child_xpriv.sign_hasher(digest.clone())?;
//! child_xpub.verify_hasher(digest, &sig)?;
//!
//! child_xpub.to_base58();
//! # Ok(())
//! # }
//! ```

pub use k256::ecdsa;

#[macro_use]
pub(crate) mod macros;

/// Base58check helpers, network version prefixes, inherent key (de)serialization, and serde helpers for other networks.
pub mod enc;

/// `DerivationPath` type and tooling for parsing it from strings
pub mod path;

/// Low-level types
pub mod primitives;

/// Extended keys and related functionality
pub mod xkeys;

/// Provides keys that are coupled with their derivation path
pub mod derived;

/// Quickstart types and traits
pub mod prelude;

use thiserror::Error;

/// The hardened derivation flag. Keys at or above this index are hardened.
pub const BIP32_HARDEN: u32 = 0x8000_0000;

#[doc(hidden)]
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Errors for this library
#[derive(Debug, Error)]
pub enum Bip32Error {
    /// Error bubbled up from the backend
    #[error("k256 error")]
    BackendError(/*#[from]*/ ecdsa::Error),

    /// Error bubbled up from the backend
    #[error("elliptic curve error")]
    EllipticCurveError(/*#[from]*/ k256::elliptic_curve::Error),

    /// Error bubbled up froom std::io
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// Master key seed generation received <16 bytes
    #[error("Master key seed generation received <16 bytes")]
    SeedTooShort,

    /// HMAC I_l was invalid during key generations.
    #[error("HMAC left segment was 0 or greated than the curve order. How?")]
    InvalidKey,

    /// pted to derive the hardened child of an xpub
    #[error("Attempted to derive the hardened child of an xpub")]
    HardenedDerivationFailed,

    /// Attempted to tweak an xpriv or xpub directly
    #[error("Attempted to tweak an xpriv or xpub directly")]
    BadTweak,

    /// Unrecognized version when deserializing xpriv
    #[error("Version bytes 0x{0:x?} don't match any network xpriv version bytes")]
    BadXPrivVersionBytes([u8; 4]),

    /// Unrecognized version when deserializing xpub
    #[error("Version bytes 0x{0:x?} don't match any network xpub version bytes")]
    BadXPubVersionBytes([u8; 4]),

    /// Bad padding byte on serialized xprv
    #[error("Expected 0 padding byte. Got {0}")]
    BadPadding(u8),

    /// A base58check payload that is not exactly one serialized extended key long
    #[error("Expected a 78-byte serialized key. Got {0} bytes")]
    BadPayloadLength(usize),

    /// Bad Checks on b58check
    #[error("Checksum mismatch on b58 deserialization")]
    BadB58Checksum,

    /// Bubbled up error from bs58 library
    #[error(transparent)]
    B58Error(#[from] bs58::decode::Error),

    /// Parsing an string derivation failed because an index string was malformatted
    #[error("Malformatted index during derivation: {0}")]
    MalformattedDerivation(String),
}

impl From<ecdsa::Error> for Bip32Error {
    fn from(e: ecdsa::Error) -> Self {
        Self::BackendError(e)
    }
}

impl From<k256::elliptic_curve::Error> for Bip32Error {
    fn from(e: k256::elliptic_curve::Error) -> Self {
        Self::EllipticCurveError(e)
    }
}

impl From<std::convert::Infallible> for Bip32Error {
    fn from(_i: std::convert::Infallible) -> Self {
        unimplemented!("unreachable, but required by type system")
    }
}

// Enables `std` on primeorder for k256's `precomputed-tables`, without
// k256's `std` (which pulls in getrandom).
use primeorder as _;
