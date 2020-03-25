use bech32::{
    FromBase32,
    ToBase32,
    u5,
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
    let (version_and_len, payload) = v.split_at(2);
    let mut v = vec![u5::try_from_u8(version_and_len[0])?];
    v.extend(&payload.to_base32());
    b32_encode(hrp, &v).map_err(|v| v.into())
}

pub fn decode_bech32(expected_hrp: &str, s: &str) -> EncodingResult<Vec<u8>> {
    let (hrp, data) = b32_decode(&s)?;
    if hrp != expected_hrp { return Err(EncodingError::WrongHRP{got: hrp, expected: expected_hrp.to_owned()}) }

    let (v, p) = data.split_at(1);
    let payload = Vec::from_base32(&p)?;
    let mut s: Vec<u8> = vec![v[0].to_u8(), payload.len() as u8];
    s.extend(&payload);
    Ok(s)
}

pub fn encode_base58(version: u8, v: &[u8]) -> String {
    v.to_base58check(version)
}

pub fn decode_base58(expected_version: u8, s: &str) -> EncodingResult<Vec<u8>> {
    let (version, data) = s.from_base58check()?;
    if version != expected_version { return Err(EncodingError::WrongVersion{got: version, expected: expected_version}) };
    Ok(data)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_should_encode_and_decode_bech32() {
        let hrp = "bc";
        let addrs = [
            "bc1q233q49ve8ysdsztqh9ue57m6227627j8ztscl9",
            "bc1qaqm8wh8sr6gfx49mdpz3w70z48xdh0pzlf5kgr",
            "bc1qjl8uwezzlech723lpnyuza0h2cdkvxvh54v3dn",
            "bc1qn0q63kkp3rj5wyap5fzymlvat28cu2s87tgzu6",
            "bc1qnsupj8eqya02nm8v6tmk93zslu2e2z8chlmcej",
            "bc1qmcwrdlcqrwcfs6654m8zvmzdmtpuvcxuzn9ahy",
            "bc1qvyyvsdcd0t9863stt7u9rf37wx443lzasg0usy",
            "bc1qza7dfgl2q83cf68fqkkdd754qx546h4u9vd9tg",
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
        ];
        for addr in addrs.iter() {
            let s = decode_bech32(&hrp, addr).unwrap();
            let reencoded = encode_bech32(&hrp, &s).unwrap();
            assert_eq!(*addr, reencoded);
        }
    }

    #[test]
    fn it_should_encode_and_decode_base58_pkh() {
        let version = 0x00;
        let addrs = [
            "1AqE7oGF1EUoJviX1uuYrwpRBdEBTuGhES",
            "1J2kECACFMDPyYjCBddKYbtzJMc6kv5FbA",
            "1ADKfX19iy3EFUoG5qGLSHNXb4c1SSHFNF",
            "12cKuAyj2jmrmMPBMtoeAt47DrJ5WRK2R5",
            "19R4yak7BGX8fcWNvtuuTSjQGC43U4qadJ",
            "1MT3dyC8YgEGY37yPwPtnvyau8HjGiMhhM",
            "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s",
            "1HMPBDt3HAD6o3zAxotBCS9o8KqCuYoapF",
            "16o4roRP8dapRJraVNnw99xBh3J1Wkk5m8",
        ];
        for addr in addrs.iter() {
            let s = decode_base58(version, addr).unwrap();
            let reencoded = encode_base58(version, &s);
            assert_eq!(*addr, reencoded);
        }
    }

    #[test]
    fn it_should_encode_and_decode_base58_sh() {
        let version = 0x05;
        let addrs = [
            "3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2",
            "35mpC7r8fGrt2WTBTkQ56xBgm1k1QCY9CQ",
            "345KNsztA2frN7V2TTZ2a9Vt6ojH8VSXFM",
            "37QxcQb7U549M1QoDpXuRZMcTjRF52mfjx",
            "377mKFYsaJPsxYSB5aFfx8SW3RaN5BzZVh",
            "3GPM5uAPoqJ4CAst3GiraHPGFxSin6Ch2b",
            "3LVq5zEBW48DjrqtmExR1YYDfJLmp8ryQE",
            "3GfrmGENZFbV4rMWUxUxeo2yUnEnSDQ5BP",
            "372sRbqCNQ1xboWCcc7XSbjptv8pzF9sBq",
        ];
        for addr in addrs.iter() {
            let s = decode_base58(version, addr).unwrap();
            let reencoded = encode_base58(version, &s);
            assert_eq!(*addr, reencoded);
        }
    }

    #[test]
    fn it_should_error_on_wrong_version_and_hrp_and_invalid_addrs() {
        match decode_bech32("tb", "bc1q233q49ve8ysdsztqh9ue57m6227627j8ztscl9") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::WrongHRP{got: _, expected: _}) => {},
            _ => assert!(false, "Got the wrong error {:?}"),
        }
        match decode_base58(1, "3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::WrongVersion{got: _, expected: _}) => {},
            _ => assert!(false, "Got the wrong error"),
        }
        match decode_bech32("bc", "bc1qqh9ue57m6227627j8ztscl9") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::BechError(_)) => {},
            _ => assert!(false, "Got the wrong error"),
        }
        match decode_base58(5, "3HXNf6Waje5YFsLEQZ2") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::B58Error(_)) => {},
            _ => assert!(false, "Got the wrong error"),
        }
    }
}
