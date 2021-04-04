//! Contains simplified access to `bech32` encoder/decoder for Handshake
//! addresses. Also defines common encoder errors.

use bech32::Error as BechError;
use coins_core::enc::bases::{
    decode_bech32 as b32_decode, encode_bech32 as b32_encode, EncodingError, EncodingResult,
};

/// Encode a byte vector to bech32. This function expects `v` to be a witness program, and will
/// return an `UnknownScriptType` if it does not meet the witness program format.
pub fn encode_bech32(hrp: &str, v: &[u8]) -> EncodingResult<String> {
    if v.len() < 2 {
        return Err(BechError::InvalidLength.into());
    }

    let (version_and_len, payload) = v.split_at(2);

    let version = version_and_len[0];
    let len = version_and_len[1];

    if version > 31 {
        return Err(EncodingError::SegwitVersionError(version_and_len[0]));
    }

    if len as usize != payload.len() {
        return Err(EncodingError::UnknownScriptType);
    };

    b32_encode(hrp, version, payload)
}

/// Decode a witness program from a bech32 string. Caller specifies an expected HRP. If a
/// different HRP is found, returns `WrongHrp`.
pub fn decode_bech32(expected_hrp: &str, s: &str) -> EncodingResult<Vec<u8>> {
    let (version, data) = b32_decode(expected_hrp, &s)?;

    let mut s: Vec<u8> = vec![version, data.len() as u8];
    s.extend(&data);

    Ok(s)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_should_encode_and_decode_bech32() {
        let hrp = "hs";
        let addrs = [
            // p2wpkh
            "hs1qz3wfydjg89swsmjpa5k3mpq0ktkk46vn6lx2a3",
            "hs1qc08ydvkntcnln5kahpa5xtc5r0uyt9ertmkfnn",
            "hs1q4uahu74wey3vewhv9x2t5chkn8lskhrpxpg6x5",
            "hs1q4k44fs86asnz6qd7jn5cyf9rnvqy997lm34wc9",
            "hs1qc93zk2nknfz84xd8r5chv2exttxauv8dlqs45e",
            "hs1q706h0gh54zs602tll53zvj6wjjg79vxkxwzqym",
            "hs1qrq7qkl3p4lvdhkeks3za344d8a2yzllzgjdmzk",
            "hs1qdd0pgffjze70uas5vudsds9w36nys3saqme8ye",
            // p2wsh
            "hs1q4fx5udfmzls9z5gvvndqu22m66njapqgkdcfxnryusgaxemru4ws0swpcd",
            "hs1qg5eeg43trcd7xgl8mv8yyu8jygeqddaeyglqdryycr7g56yuajhq5g6eye",
            "hs1qlyfz43he0n5qmu5c98dwt70fc4ruvhjdkns5suedtu5tdj75tv3quk9qv9",
            "hs1qjwflnutemp0afjy0tlhqeg3edmczlm0avpefpx239kpctk482lqqafq2xm",
            "hs1qv2r3ld83e3mz0sa3uud9duyy0k9qzm7wz2dr7zux8hp80aql9wzqxgjlj6",
            // opreturn
            "hs1l38uu5j094yl52qk0f5putqlltyh3ylghlnu3j98xaa6zw2eztretj2rvtc5rm6dk57r0mg",
            "hs1l9dqwypjc5f8pht9sxguz2gz85v8qmmhgvl8n2tau43quyhlf476e4q25zdxdvs85qn543a",
            "hs1lyshr2p9x6xncngq8w2xkjakcy2rnja799dz4faz2k7jty4wsc3c223zxl2cj7e09gmnlxw",
            "hs1lw5rthtzvnyfgjmdvmwptcy8yx2rfdresyegeua2v74zyy474jhf0wlp3jjjjewt5mzjult",
            "hs1l8axd3n4esdkn6v68k9a2suuhw204ef0sgsctj4l4yw0z6x8n38an64fzp8wym5w4zr36un",
        ];
        for addr in addrs.iter() {
            let s = decode_bech32(&hrp, addr).unwrap();
            let reencoded = encode_bech32(&hrp, &s).unwrap();
            assert_eq!(*addr, reencoded);
        }
    }

    #[test]
    fn it_should_error_on_wrong_version_and_hrp_and_invalid_addrs() {
        match decode_bech32("ts", "hs1qrq7qkl3p4lvdhkeks3za344d8a2yzllzgjdmzk") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::WrongHrp {
                got: _,
                expected: _,
            }) => {}
            _ => assert!(false, "Got the wrong error"),
        }
        match decode_bech32("hs", "hs1qrq7qkl3p4lvdhkeks3za34") {
            Ok(_) => assert!(false, "expected an error"),
            Err(EncodingError::BechError(_)) => {}
            _ => assert!(false, "Got the wrong error"),
        }
    }
}
