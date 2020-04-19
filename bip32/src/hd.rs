use sha2::Sha512;
use hmac::{Hmac, Mac};

use crate::{
    Bip32Error,
    keys,
    xkeys::{self, ChainCode, XPriv}
};

type HmacSha512 = Hmac<Sha512>;

const SEED: &'static [u8; 12] = b"Bitcoin seed";

/// Perform `HmacSha512` and split the output into left and right segments
pub fn hmac_and_split(seed: &[u8], data: &[u8]) -> ([u8; 32], ChainCode) {
    let mut mac = HmacSha512::new_varkey(seed).expect("key length is ok");
    mac.input(data);
    let result = mac.result().code();

    let mut left = [0u8; 32];
    left.copy_from_slice(&result[..32]);

    let mut right = [0u8; 32];
    right.copy_from_slice(&result[32..]);

    (left, ChainCode(right))
}


/// Generate a master node from a seed
///
/// # Important:
///
/// Use a seed of AT LEAST 128 bits.
pub fn generate_master_node(data: &[u8], hint: Option<xkeys::Hint>) -> Result<XPriv, Bip32Error> {
    if data.len() < 16 {
        return Err(Bip32Error::SeedTooShort);
    }
    let parent = xkeys::KeyFingerprint([0u8; 4]);
    let (key, chain_code) = hmac_and_split(SEED, data);
    if key == [0u8; 32] || key > secp256k1::constants::CURVE_ORDER {
        return Err(Bip32Error::InvalidKey);
    }
    let privkey = keys::Privkey::from_array(key);
    Ok(XPriv::new(0, parent, 0, privkey, chain_code, hint.unwrap_or(xkeys::Hint::SegWit)))
}
