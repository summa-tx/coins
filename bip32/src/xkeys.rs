use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{
    curve::model::{ScalarDeserialize, Secp256k1Backend},
    keys::{GenericPrivkey, GenericPubkey},
    model::*,
    Bip32Error, BIP32_HARDEN, CURVE_ORDER,
};

type HmacSha512 = Hmac<Sha512>;

/// A BIP32 Extended privkey using the library's compiled-in secp256k1 backend.
#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub type XPriv<'a> = GenericXPriv<'a, crate::curve::Secp256k1<'a>>;

/// A BIP32 Extended pubkey using the library's compiled-in secp256k1 backend.
#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub type XPub<'a> = GenericXPub<'a, crate::curve::Secp256k1<'a>>;

/// Default BIP32
pub const SEED: &[u8; 12] = b"Bitcoin seed";

pub(crate) fn hmac_and_split(seed: &[u8], data: &[u8]) -> ([u8; 32], ChainCode) {
    let mut mac = HmacSha512::new_varkey(seed).expect("key length is ok");
    mac.input(data);
    let result = mac.result().code();

    let mut left = [0u8; 32];
    left.copy_from_slice(&result[..32]);

    let mut right = [0u8; 32];
    right.copy_from_slice(&result[32..]);

    (left, ChainCode(right))
}

/// Info associated with an extended key
#[derive(Copy, Clone, Debug, PartialEq)]
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
}

impl XKey for XKeyInfo {
    fn depth(&self) -> u8 {
        self.depth
    }
    fn parent(&self) -> KeyFingerprint {
        self.parent
    }
    fn index(&self) -> u32 {
        self.index
    }
    fn chain_code(&self) -> ChainCode {
        self.chain_code
    }
    fn hint(&self) -> Hint {
        self.hint
    }
}

/// A BIP32 Extended privkey. This key is genericized to accept any compatibile backend.
#[derive(Clone, Debug, PartialEq)]
pub struct GenericXPriv<'a, T: Secp256k1Backend<'a>> {
    /// The extended key information
    pub info: XKeyInfo,
    /// The associated secp256k1 key
    pub privkey: GenericPrivkey<'a, T>,
}

inherit_has_privkey!(GenericXPriv.privkey);
inherit_backend!(GenericXPriv.privkey);

impl<'a, T: Secp256k1Backend<'a>> GenericXPriv<'a, T> {
    /// Instantiate a master node using a custom HMAC key.
    pub fn custom_master_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
        backend: &'a T,
    ) -> Result<GenericXPriv<'a, T>, Bip32Error> {
        if data.len() < 16 {
            return Err(Bip32Error::SeedTooShort);
        }
        let parent = KeyFingerprint([0u8; 4]);
        let (key, chain_code) = hmac_and_split(hmac_key, data);
        if key == [0u8; 32] || key > CURVE_ORDER {
            return Err(Bip32Error::InvalidKey);
        }
        let privkey = T::Privkey::from_privkey_array(key)?;
        Ok(GenericXPriv {
            info: XKeyInfo {
                depth: 0,
                parent,
                index: 0,
                chain_code,
                hint: hint.unwrap_or(Hint::SegWit),
            },
            privkey: GenericPrivkey {
                key: privkey,
                backend: Some(backend),
            },
        })
    }

    /// Generate a master node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn root_from_seed(
        data: &[u8],
        hint: Option<Hint>,
        backend: &'a T,
    ) -> Result<GenericXPriv<'a, T>, Bip32Error> {
        Self::custom_master_node(SEED, data, hint, backend)
    }

    /// Derive the corresponding xpub
    pub fn to_xpub(&self) -> Result<GenericXPub<'a, T>, Bip32Error> {
        Ok(GenericXPub {
            info: self.info,
            pubkey: self.privkey.derive_verifying_key()?,
        })
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasXKeyInfo for GenericXPriv<'a, T> {
    fn xkey_info(&self) -> &XKeyInfo {
        &self.info
    }
}

impl<'a, T: Secp256k1Backend<'a>> SigningKey<'a, T> for GenericXPriv<'a, T> {
    /// The corresponding verifying key
    type VerifyingKey = GenericXPub<'a, T>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        self.to_xpub()
    }
}

impl<'a, T: Secp256k1Backend<'a>> DerivePrivateChild<'a, T> for GenericXPriv<'a, T> {
    fn derive_private_child(&self, index: u32) -> Result<GenericXPriv<'a, T>, Bip32Error> {
        let hardened = index >= BIP32_HARDEN;

        let mut data: Vec<u8> = vec![];
        if hardened {
            data.push(0);
            data.extend(&self.privkey_bytes());
            data.extend(&index.to_be_bytes());
        } else {
            data.extend(&self.derive_pubkey_bytes()?.to_vec());
            data.extend(&index.to_be_bytes());
        };

        let (tweak, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        let privkey = self
            .backend()?
            .tweak_privkey(&self.privkey(), tweak)
            .map(|k| GenericPrivkey {
                key: k,
                backend: self.backend().ok(),
            })
            .map_err(Into::into)?;

        Ok(GenericXPriv {
            info: XKeyInfo {
                depth: self.depth() + 1,
                parent: self.derive_fingerprint()?,
                index,
                chain_code,
                hint: self.hint(),
            },
            privkey,
        })
    }
}

/// A BIP32 Extended privkey. This key is genericized to accept any compatibile backend.
#[derive(Clone, Debug, PartialEq)]
pub struct GenericXPub<'a, T: Secp256k1Backend<'a>> {
    /// The extended key information
    pub info: XKeyInfo,
    /// The associated secp256k1 key
    pub pubkey: GenericPubkey<'a, T>,
}

inherit_has_pubkey!(GenericXPub.pubkey);
inherit_backend!(GenericXPub.pubkey);

impl<'a, T: Secp256k1Backend<'a>> GenericXPub<'a, T> {
    /// Derive an XPub from an xpriv
    pub fn from_xpriv(xpriv: &GenericXPriv<'a, T>) -> Result<GenericXPub<'a, T>, Bip32Error> {
        xpriv.to_xpub()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasXKeyInfo for GenericXPub<'a, T> {
    fn xkey_info(&self) -> &XKeyInfo {
        &self.info
    }
}

impl<'a, T: Secp256k1Backend<'a>> VerifyingKey<'a, T> for GenericXPub<'a, T> {
    type SigningKey = GenericXPriv<'a, T>;
}

impl<'a, T: Secp256k1Backend<'a>> DerivePublicChild<'a, T> for GenericXPub<'a, T> {
    fn derive_public_child(&self, index: u32) -> Result<GenericXPub<'a, T>, Bip32Error> {
        if index >= BIP32_HARDEN {
            return Err(Bip32Error::HardenedKey);
        }
        let mut data: Vec<u8> = self.pubkey_bytes().to_vec();
        data.extend(&index.to_be_bytes());

        let (offset, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        // TODO: check for point at infinity
        if offset > CURVE_ORDER {
            return self.derive_public_child(index + 1);
        }

        let pubkey = self
            .backend()?
            .tweak_pubkey(&self.pubkey(), offset)
            .map(|k| GenericPubkey {
                key: k,
                backend: self.backend().ok(),
            })
            .map_err(Into::into)?;

        Ok(Self {
            info: XKeyInfo {
                depth: self.depth() + 1,
                parent: self.fingerprint(),
                index,
                chain_code,
                hint: self.hint(),
            },
            pubkey,
        })
    }
}
