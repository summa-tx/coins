use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::enc::NetworkVersions;

/// We treat the bip32 xpub bip49 ypub and bip84 zpub convention as a hint
/// regarding address type. Downstream crates are free to follow or ignore
/// these hints when generating addresses from extended keys.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Hint {
    /// Standard Bip32 hint
    Legacy,
    /// Bip32 + Bip49 hint for Witness-via-P2SH
    Compatibility,
    /// Bip32 + Bip84 hint for Native SegWit
    SegWit,
}

/// A 4-byte key fingerprint
#[derive(Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct KeyFingerprint(pub [u8; 4]);

impl From<[u8; 4]> for KeyFingerprint {
    fn from(v: [u8; 4]) -> Self {
        Self(v)
    }
}

impl KeyFingerprint {
    /// Determines if the slice represents the same key fingerprint
    pub fn eq_slice(self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl std::fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("KeyFingerprint {:x?}", self.0))
    }
}

/// A 32-byte chain code. Compared in constant time.
#[derive(Debug, Clone, Copy, Zeroize)]
pub struct ChainCode(pub [u8; 32]);

impl ConstantTimeEq for ChainCode {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ChainCode {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ChainCode {}

impl From<[u8; 32]> for ChainCode {
    fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}

impl ChainCode {
    /// The chain code fixed by BIP-328 for MuSig2 synthetic xpubs: `sha256("MuSig2MuSig2MuSig2")`.
    ///
    /// See <https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki>.
    pub const MUSIG2_SYNTHETIC_ROOT: Self = Self([
        0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57,
        0x76, 0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3,
        0x89, 0x65,
    ]);
}

/// Info associated with an extended key
#[derive(Copy, Clone, Debug)]
pub struct XKeyInfo {
    /// The key depth in the HD tree
    pub depth: u8,
    /// The 4-byte Fingerprint of the parent
    pub parent: KeyFingerprint,
    /// The 4-byte derivation index of the key. If the most-significant byte is set, this key is
    /// hardened
    pub index: u32,
    /// The 32-byte chain code used to generate child keys
    pub chain_code: ChainCode,
    /// The key's stanadard output type preference
    pub hint: Hint,
    /// The network whose version bytes this key serializes with
    pub network: &'static NetworkVersions,
}

/// Compares the key's position and chain code. Ignores `hint` and `network`, because both are
/// presentation metadata, not key identity.
impl PartialEq for XKeyInfo {
    fn eq(&self, other: &XKeyInfo) -> bool {
        self.depth == other.depth
            && self.parent == other.parent
            && self.index == other.index
            && self.chain_code == other.chain_code
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn musig2_synthetic_root_chain_code_matches_bip328() {
        // BIP-328: fixed chain code for synthetic xpubs is sha256("MuSig2MuSig2MuSig2")
        // https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki
        let expected = Sha256::digest(b"MuSig2MuSig2MuSig2");
        assert_eq!(ChainCode::MUSIG2_SYNTHETIC_ROOT.0[..], expected[..]);
    }
}
