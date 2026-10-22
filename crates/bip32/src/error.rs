use k256::ecdsa;
use thiserror::Error;

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
    #[error("Expected a 78-byte serialized key")]
    BadPayloadLength,

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
