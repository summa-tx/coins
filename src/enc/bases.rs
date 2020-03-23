use bech32::{
    FromBase32,
    ToBase32,
    Error as BechError,
    encode as b32_encode,
    decode as b32_decode,
};

use base58check::{
    FromBase58Check,
    FromBase58CheckError,
    ToBase58Check
};

use thiserror::Error;



#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Address {
    PKH(String),
    SH(String),
    WPKH(String),
    WSH(String)
}

#[derive(Debug, Error)]
pub enum EncodingError {
    /// Returned when Script type is unknown. May be non-standard or newer than lib version.
    #[error("Non-standard Script type")]
    UnknownScriptType,

    /// Bech32 HRP does not match the current network.
    #[error("Bech32 HRP does not match. \nGot {:?} expected {:?} Hint: Is this address for another network?", got, expected)]
    WrongHRP{got: String, expected: String},

    /// Base58Check version does not match the current network
    #[error("Base58Check version does not match. \nGot {:?} expected {:?} Hint: Is this address for another network?", got, expected)]
    WrongVersion{got: u8, expected: u8},

    /// Bubbled up error from base58check library
    #[error("FromBase58CheckError: {:?}", .0)]
    B58Error(FromBase58CheckError),

    /// Bubbled up error from bech32 library
    #[error("BechError: {:?}", .0)]
    BechError(#[from] BechError),
}

/// Impl explicitly because FromBase58CheckError doesn't implement the std error format
impl From<FromBase58CheckError> for EncodingError {
    fn from(e: FromBase58CheckError) -> Self {
        EncodingError::B58Error(e)
    }
}

pub type EncodingResult<T> = Result<T, EncodingError>;

pub fn encode_bech32(hrp: &str, v: &[u8]) -> EncodingResult<String> {
    b32_encode(hrp, &v.to_base32()).map_err(|v| v.into())
}

pub fn decode_bech32(expected_hrp: &str, s: &str) -> EncodingResult<Vec<u8>> {
    let (hrp, data) = b32_decode(&s)?;
    if hrp != expected_hrp { return Err(EncodingError::WrongHRP{got: hrp, expected: expected_hrp.to_owned()}) }
    let v = Vec::<u8>::from_base32(&data)?;
    Ok(v)
}

pub fn encode_base58(version: u8, v: &[u8]) -> String {
    v.to_base58check(version)
}

pub fn decode_base58(expected_version: u8, s: &str) -> EncodingResult<Vec<u8>> {
    let (version, data) = s.from_base58check()?;
    if version != expected_version { return Err(EncodingError::WrongVersion{got: version, expected: expected_version}) };
    Ok(data)
}
