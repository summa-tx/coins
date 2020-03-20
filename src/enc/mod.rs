// pub mod bases;
// pub mod addresses;
// pub mod legacy;
// pub mod addr;

// pub use bases::*;
// pub use addresses::*;
// pub use legacy::*;
// pub use addr::*;

use bech32::{
    encode as b32_encode,
    decode as b32_decode,
    Error as BechError,
    FromBase32,
};
use bech32::{ToBase32};

use base58check::{
    FromBase58Check,
    FromBase58CheckError,
    ToBase58Check
};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Address {
    PKH(String),
    SH(String),
    WPKH(String),
    WSH(String)
}

pub enum EncodingError {
    UnknownScriptType,
    WrongHRP(String),
    WrongPKHVersion(u8),
    WrongSHVersion(u8),
    B58Error(FromBase58CheckError),
    BechError(BechError),
}

pub type EncodingResult<T> = Result<T, EncodingError>;

impl From<BechError> for EncodingError {
    fn from(e: BechError) -> Self {
        EncodingError::BechError(e)
    }
}

impl From<FromBase58CheckError> for EncodingError {
    fn from(e: FromBase58CheckError) -> Self {
        EncodingError::B58Error(e)
    }
}

pub fn encode_bech32(hrp: &str, v: &[u8]) -> EncodingResult<String> {
    b32_encode(hrp, &v.to_base32()).map_err(|v| v.into())
}

pub fn decode_bech32(expected_hrp: &str, s: &str) -> EncodingResult<Vec<u8>> {
    let (hrp, data) = b32_decode(&s)?;
    if hrp != expected_hrp { return Err(EncodingError::WrongHRP(hrp)) }
    let v = Vec::<u8>::from_base32(&data)?;
    Ok(v)
}

pub fn encode_base58(version: u8, v: &[u8]) -> String {
    v.to_base58check(version)
}

pub fn decode_base58(expected_version: u8, s: &str) -> EncodingResult<Vec<u8>> {
    let (version, data) = s.from_base58check()?;
    if version != expected_version { return Err(EncodingError::WrongPKHVersion(version)) };
    Ok(data)
}
