//! Contains simplified access to `bech32` and `base58check` encoder/decoder for Bitcoin
//! addresses. Also defines common encoder errors.

use coins_core::enc::{
    EncodingError, EncodingResult, encode_bech32, decode_bech32
};
use bech32::{
    Error as BechError,
};

/// Encode a byte vector to bech32. This function expects `v` to be a witness program, and will
/// return an `UnknownScriptType` if it does not meet the witness program format.
pub fn bitcoin_encode_bech32(hrp: &str, v: &[u8]) -> EncodingResult<String> {
    if v.len() < 2 || v.len() > 40 {
        return Err(BechError::InvalidLength.into());
    }

    let (version_and_len, payload) = v.split_at(2);
    if version_and_len[0] > 16 || version_and_len[1] as usize != payload.len() {
        return Err(EncodingError::UnknownScriptType);
    };

    encode_bech32(hrp, version_and_len[0], &payload)
}

/// Decode a witness program from a bech32 string. Caller specifies an expected HRP. If a
/// different HRP is found, returns `WrongHRP`.
pub fn bitcoin_decode_bech32(expected_hrp: &str, s: &str) -> EncodingResult<Vec<u8>> {
    let (version, data) = decode_bech32(expected_hrp, s)?;

    // Encode as witness program: witness version 0, then len(payload), then payload.
    let mut s: Vec<u8> = vec![version, data.len() as u8];
    s.extend(&data);

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
            let s = bitcoin_decode_bech32(&hrp, addr).unwrap();
            let reencoded = bitcoin_encode_bech32(&hrp, &s).unwrap();
            assert_eq!(*addr, reencoded);
        }
    }
}
