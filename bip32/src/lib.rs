//! This crate provides a basic implementation of BIP32, BIP49, and BIP84 with configurable
//! backends. It can be easily adapted to support other networks, using the paramaterizable
//! encoder.
//!
//! Typically, users will want to use the `MainnetEncoder`, `DerivedXPub`, `DerivedXPriv` types,
//! which are available at the crate root. If key derivations are unknown, use the `XPub` and
//! `XPriv` objects instead. These may be deserialized using a network-specific `Encoder` from the
//! `enc` module.
//!
//! Useful traits will need to be imported from the `enc` or `model` modules. Most users will want
//! `model::SigningKey`, `model::VerifyingKey`, `enc::Encoder`, and `enc::HasPubkey`.
//!
//! # Warnings:
//!
//! - This crate is NOT designed to be used in adversarial environments.
//! - This crate has NOT had a comprehensive security review.
//! - It is not clear whether the rust-secp backend's functions are constant-time.
//!
//! # Usage
//!
//! Most key objects need a backend. They can be instantiated without one, but most operations
//! you want (e.g. signing, verifying, key derivation) will fail at runtime. Simple usage:
//!
//! ```
//! use rmn_bip32::{
//!     Bip32Error, Secp256k1, XPub, XPriv,
//!     enc::{Encoder, MainnetEncoder},
//!     model::*,
//!     curve::model::*,
//! };
//!
//! # fn main() -> Result<(), Bip32Error> {
//! let digest = [1u8; 32];
//!
//! // `init` sets up a new `lazy_static` backend. Successive calls will re-use that backend
//! // without needing to re-initialize it.
//! let backend = Secp256k1::init();
//! let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
//!
//! // Encoders are network specific due to the bip32 version byte spec
//! let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(&backend))?;
//!
//! let child_xpriv = xpriv.derive_private_child(33)?;
//! let sig = child_xpriv.sign_digest(digest)?;
//!
//! // Signing key types are associated with verifying key types. You can always derive a pubkey
//! // from a privkey using `derive_verifying_key()`.
//! let child_xpub = child_xpriv.derive_verifying_key()?;
//! child_xpub.verify_digest(digest, &sig);
//!
//! sig.to_der(); // serialize to der-encoded byte-array
//! MainnetEncoder::xpub_to_base58(&child_xpub)?;
//! # Ok(())
//! # }
//! ```
//!
//! The backend is configurable. By default, it uses bindings to Pieter Wuille's C `libsecp256k1`.
//! Turning off standard features, and compiling with the `rust-secp` feature will use a pure rust
//! backend. Users can provide their own backend by implementing the `Secp256k1Backend` trait. In
//! this case, you will need to use the `Generic` variants of the structs found in the `keys`,
//! `xkeys`, and `derived modules.` These backends are mutually exclusive. So to use `rust-secp`
//! you must disable default features. Compilation will fail otherwise.
//!
//! Additionally, both provided backends allow user-provided context objects via the
//! `Secp256k1Backend::from_context()` method. We also provide access to `lazy_static` on-demand
//! contexts via `Secp256k1Backend::init()`. This has a 1-time cost. The
//! `rust-secp-static-context` allows for compilation-time generation of the context, but must
//! be used with the `rust-secp` backend.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

#[cfg(not(feature = "rust-secp-static-context"))]
#[macro_use]
extern crate lazy_static;

#[cfg_attr(tarpaulin, skip)]
#[macro_use]
pub(crate) mod prelude;

/// Low-level types
pub mod primitives;

/// Keys and related functionality
pub mod keys;

/// Extended keys and related functionality
pub mod xkeys;

/// Network-differentiated encoders for extended keys.
pub mod enc;

/// The Secp256k1 backend and its associated traits. Compiled-in backends may be selected using
/// crate features. Generally, this module's traits shouldn't be used directly, with the notable
/// exception of `SigSerialize` and `RecoverableSigSerialize`.
#[cfg_attr(tarpaulin, skip)]
pub mod curve;

/// Traits and other high-level model description for Bip32 keys.
pub mod model;

/// `DerivationPath` type and tooling for parsing it from strings
pub mod path;

/// Provides keys that are coupled with their derivation path
pub mod derived;

pub use enc::MainnetEncoder;
pub use model::*;
pub use primitives::KeyFingerprint;

pub use crate::{
    curve::{RecoverableSignature, Secp256k1, Signature},
    derived::{DerivedXPriv, DerivedXPub},
    keys::{Privkey, Pubkey},
    xkeys::{XPriv, XPub},
};

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
    #[error(transparent)]
    BackendError(#[from] crate::curve::Error),

    /// General wrapper for errors from custom backends
    #[error("Custom backend returned error with info: {0}")]
    CustomBackendError(String),

    /// Error bubbled up froom std::io
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error bubbled up froom Ser
    #[error(transparent)]
    SerError(#[from] riemann_core::ser::SerError),

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

    /// No backed in xtended key
    #[error("Attempted to operate on an extended key without supplying a backend")]
    NoBackend,

    /// Bad padding byte on serialized xprv
    #[error("Expected 0 padding byte. Got {0}")]
    BadPadding(u8),

    /// Bad Checks on b58check
    #[error("Checksum mismatch on b58 deserialization")]
    BadB58Checksum,

    /// Bubbled up error from bs58 library
    #[error(transparent)]
    B58Error(#[from] bs58::decode::Error),

    /// Parsing an string derivation failed because an index string was malformatted
    #[error("Malformatted index during derivation: {0}")]
    MalformattedDerivation(String),

    /// Attempted to deserialize a DER signature to a recoverable signature.
    #[error("Attempted to deserialize a DER signature to a recoverable signature. Use deserialize_vrs instead")]
    NoRecoveryID,

    /// Attempted to deserialize a very long path
    #[error("Invalid Bip32 Path.")]
    InvalidBip32Path,
}

impl From<std::convert::Infallible> for Bip32Error {
    fn from(_i: std::convert::Infallible) -> Self {
        unimplemented!("unreachable, but required by type system")
    }
}
