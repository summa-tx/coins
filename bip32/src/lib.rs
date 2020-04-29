//! This crate provides a basic implementation of BIP32, BIP49, and BIP84 with configurable
//! backends. It can be easily adapted to support other networks, using the paramaterizable
//! encoder.
//!
//! Typically, users will want to use the `MainnetEncoder`, `XPub`, `XPriv` objects, which are
//! available at the crate root.
//!
//! The objects provided need a backend. They can be instantiated without one, but many basic
//! operations (e.g. signing, verifying, key derivation) will fail. Simple usage:
//!
//! ```
//! use rmn_bip32::{
//!     Bip32Error,
//!     Secp256k1,
//!     enc::{Encoder, MainnetEncoder},
//!     model::*,
//!     curve::model::*,
//!     xkeys::{XPub, XPriv},
//! };
//!
//! # fn main() -> Result<(), Bip32Error> {
//! let digest = [1u8; 32];
//! let backend = Secp256k1::init();
//! let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
//!
//! let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(&backend))?;
//!
//! let child = xpriv.derive_private_child(33)?;
//! let sig = child.sign_digest(digest)?;
//!
//! let child_xpub = child.to_xpub()?;
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
//! backend. Users can provide their own backend by implementing the `Secp256k1Backend` trait.
//! These backends are mutually exclusive. So to use `rust-secp` you must disable default features
//!
//! Additionally, both provided backends allow user-provided context objects via the
//! `Secp256k1Backend::from_context` method. We also provide access to `lazy_static` on-demand
//! contexts via `Secp256k1Backend::init()`. This has a 1-time cost. The
//! `rust-secp-static-context` allows for compilation-timem generation of the context, but must
//! be used with the `rust-secp` backend.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

#[cfg(not(feature = "rust-secp-static-context"))]
#[macro_use]
extern crate lazy_static;

/// Keys and related functionality
pub mod keys;

/// Extended keys and related functionality
pub mod xkeys;

/// Network-differentiated encoders for xkeys
pub mod enc;

/// The curve-math backend, selected at compile time. Defaults to native libsecp256k1 bindings.
pub mod curve;

/// Traits and other high-level model description.
pub mod model;

/// `DerivationPath` type and tooling for parsing it from strings
pub mod path;

/// Provides keys that are coupled with their derivation path
pub mod derived;

pub use enc::{Encoder, MainnetEncoder, NetworkParams, TestnetEncoder};
pub use model::*;
pub use path::{DerivationPath, KeyDerivation};


#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub use crate::{
    curve::{RecoverableSignature, Secp256k1, Signature},
    derived::{DerivedPrivkey, DerivedPubkey, DerivedXPriv, DerivedXPub,},
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
    #[cfg(any(feature = "libsecp", feature = "rust-secp"))]
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

    /// Parsing an string derivation failed because an index string was malformatted
    #[error("Malformatted index during derivation: {0}")]
    MalformattedIndex(String),

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        curve::*,
        enc::{Encoder, MainnetEncoder},
        xkeys::{XPriv},
    };

    use hex;

    struct KeyDeriv<'a> {
        pub path: &'a [u32],
        pub xpub: String,
        pub xpriv: String,
    }

    fn validate_descendant<'a>(d: &KeyDeriv, m: &XPriv<'a>) {
        let xpriv = m.derive_private_path(d.path).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&d.xpriv, xpriv.backend().ok()).unwrap();
        let deser_xpub = MainnetEncoder::xpub_from_base58(&d.xpub, xpriv.backend().ok()).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(), d.xpriv);
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(MainnetEncoder::xpub_to_base58(&xpub).unwrap(), d.xpub);
    }

    #[test]
    fn bip32_vector_1() {
        let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let backend = Secp256k1::init();

        let xpriv = xkeys::XPriv::root_from_seed(&seed, Some(Hint::Legacy), &backend).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let expected_xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let expected_xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        let deser_xpub = MainnetEncoder::xpub_from_base58(&expected_xpub, Some(&backend)).unwrap();
        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(&backend)).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(
            MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(),
            expected_xpriv
        );
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(
            MainnetEncoder::xpub_to_base58(&xpub).unwrap(),
            expected_xpub
        );

        let descendants = [
            KeyDeriv {
                path: &[0 + BIP32_HARDEN],
                xpub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw".to_owned(),
                xpriv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1],
                xpub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ".to_owned(),
                xpriv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN],
                xpub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5".to_owned(),
                xpriv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2],
                xpub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV".to_owned(),
                xpriv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2, 1000000000],
                xpub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy".to_owned(),
                xpriv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_2() {
        let seed = hex::decode(&"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let backend = Secp256k1::init();

        let xpriv = xkeys::XPriv::root_from_seed(&seed, Some(Hint::Legacy), &backend).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let expected_xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        let expected_xpriv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";

        let deser_xpub = MainnetEncoder::xpub_from_base58(&expected_xpub, Some(&backend)).unwrap();
        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(&backend)).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(
            MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(),
            expected_xpriv
        );
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(
            MainnetEncoder::xpub_to_base58(&xpub).unwrap(),
            expected_xpub
        );

        let descendants = [
            KeyDeriv {
                path: &[0],
                xpub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH".to_owned(),
                xpriv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN],
                xpub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a".to_owned(),
                xpriv: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1],
                xpub: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon".to_owned(),
                xpriv: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1, 2147483646 + BIP32_HARDEN],
                xpub: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL".to_owned(),
                xpriv: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1, 2147483646 + BIP32_HARDEN, 2],
                xpub: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt".to_owned(),
                xpriv: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_3() {
        let seed = hex::decode(&"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
        let backend = Secp256k1::init();

        let xpriv = xkeys::XPriv::root_from_seed(&seed, Some(Hint::Legacy), &backend).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let expected_xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
        let expected_xpriv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";

        let deser_xpub = MainnetEncoder::xpub_from_base58(&expected_xpub, Some(&backend)).unwrap();
        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(&backend)).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(
            MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(),
            expected_xpriv
        );
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(
            MainnetEncoder::xpub_to_base58(&xpub).unwrap(),
            expected_xpub
        );

        let descendants = [
            KeyDeriv {
                path: &[0 + BIP32_HARDEN],
                xpub: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y".to_owned(),
                xpriv: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn it_can_sign_and_verify() {
        let digest = [1u8; 32];
        let backend = Secp256k1::init();
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();

        let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(&backend)).unwrap();

        let child = xpriv.derive_private_child(33).unwrap();
        let sig = child.sign_digest(digest).unwrap();

        let child_xpub = child.to_xpub().unwrap();
        child_xpub.verify_digest(digest, &sig).unwrap();
    }

    #[test]
    fn it_can_read_keys_without_a_backend() {
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let _xpriv: XPriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, None).unwrap();
    }
}
