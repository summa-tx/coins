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
//! # Encoding
//!
//! Keys are associated with a specific network. When deserializing or parsing,
//! the network is inferred from the prefix bytes, and stored on the key. It is
//! then used when serializing. It is not advisable to change networks on a key
//! in memory.
//!
//! Other networks can create a [`enc::NetworkVersions`] struct with their own
//! prefix information, and use the helpers in the [`enc`] module to
//! (de)serialize keys with those prefixes
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

/// The crate's error type
pub mod error;

pub use error::Bip32Error;

/// The hardened derivation flag. Keys at or above this index are hardened.
pub const BIP32_HARDEN: u32 = 0x8000_0000;

#[doc(hidden)]
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

// Enables `std` on primeorder for k256's `precomputed-tables`, without
// k256's `std` (which pulls in getrandom).
use primeorder as _;
