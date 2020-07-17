//! Contains simplified access to `bech32` encoder/decoder for Handshake
//! addresses. Also defines common encoder errors.

use bech32::{
    decode as b32_decode, encode as b32_encode, u5, Error as BechError, FromBase32, ToBase32,
};

use thiserror::Error;

/// Errors that can be returned by the Bitcoin `AddressEncoder`.
#[derive(Debug, Error)]
pub enum EncodingError {
    /// Returned when ScriptPubkey type is unknown. May be non-standard or newer than lib version.
    #[error("Non-standard LockingScript type")]
    UnknownScriptType,

    /// Bech32 HRP does not match the current network.
    #[error("Bech32 HRP does not match. \nGot {:?} expected {:?} Hint: Is this address for another network?", got, expected)]
    WrongHRP {
        /// The actual HRP.
        got: String,
        /// The expected HRP.
        expected: String,
    },

    /// Invalid Segwit Version
    #[error("SegwitVersionError: {:?}", .0)]
    SegwitVersionError(u8),

    /// Bubbled up error from bech32 library
    #[error("BechError: {:?}", .0)]
    BechError(#[from] BechError),
}

/// A simple result type alias
pub type EncodingResult<T> = Result<T, EncodingError>;

/// Encode a byte vector to bech32. This function expects `v` to be a witness program, and will
/// return an `UnknownScriptType` if it does not meet the witness program format.
pub fn encode_bech32(hrp: &str, v: &[u8]) -> EncodingResult<String> {
    if v.len() < 2 {
        return Err(BechError::InvalidLength.into());
    }

    let (version_and_len, payload) = v.split_at(2);

    if version_and_len[0] > 31 {
        return Err(EncodingError::SegwitVersionError(version_and_len[0]));
    }

    if version_and_len[1] as usize != payload.len() {
        return Err(EncodingError::UnknownScriptType);
    };

    let mut v = vec![u5::try_from_u8(version_and_len[0])?];
    v.extend(&payload.to_base32());
    b32_encode(hrp, &v).map_err(|v| v.into())
}

/// Decode a witness program from a bech32 string. Caller specifies an expected HRP. If a
/// different HRP is found, returns `WrongHRP`.
pub fn decode_bech32(expected_hrp: &str, s: &str) -> EncodingResult<Vec<u8>> {

    let (hrp, data) = b32_decode(&s)?;
    if hrp != expected_hrp {
        return Err(EncodingError::WrongHRP {
            got: hrp,
            expected: expected_hrp.to_owned(),
        });
    }

    // Extract the witness version and payload
    let (v, p) = data.split_at(1);
    let payload = Vec::from_base32(&p)?;

    // Encode as witness program: witness version 0, then len(payload), then payload.
    let mut s: Vec<u8> = vec![v[0].to_u8(), payload.len() as u8];
    s.extend(&payload);

    Ok(s)
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

    /*
    #[test]
    fn it_should_error_on_wrong_version_and_hrp_and_invalid_addrs() {
        match decode_bech32("tb", "bc1q233q49ve8ysdsztqh9ue57m6227627j8ztscl9") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::WrongHRP {
                got: _,
                expected: _,
            }) => {}
            _ => assert!(false, "Got the wrong error {:?}"),
        }
        match decode_base58(1, "3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::WrongVersion {
                got: _,
                expected: _,
            }) => {}
            _ => assert!(false, "Got the wrong error"),
        }
        match decode_bech32("bc", "bc1qqh9ue57m6227627j8ztscl9") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::BechError(_)) => {}
            _ => assert!(false, "Got the wrong error"),
        }
        match decode_base58(5, "3HXNf6Waje5YFsLEQZ2") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::B58Error(_)) => {}
            _ => assert!(false, "Got the wrong error"),
        }
    }
    */
}
