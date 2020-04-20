//! This crate provides a basic implementation of BIP32 and related BIPs.

#![forbid(unsafe_code)]

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

// /// Keys and related functionality
// pub mod keys;
//
/// Extended keys and related functionality
pub mod xkeys;

/// Network-differentiated encoders for xkeys
pub mod enc;

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

    /// Error bubbled up froom std::io
    #[error(transparent)]
    IOError(#[from] std::io::Error),

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
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::backend::{Secp256k1Backend};
    use crate::enc::{Encoder, MainnetEncoder};

    #[test]
    fn it_deserializes_xpubs() {
        let backend = backend::curve::Secp256k1::init();
        let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let xpriv = xkeys::XPriv::generate_master_node(&seed, None, &backend).unwrap();

        let expected_xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let expected_pub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let deser_xpriv = MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(&backend)).unwrap();
        assert_eq!(xpriv, deser_xpriv);
    }
}
