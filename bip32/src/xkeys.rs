use bitcoin_spv::btcspv::hash160;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{model::*, Bip32Error, BIP32_HARDEN, CURVE_ORDER};

type HmacSha512 = Hmac<Sha512>;

/// Default BIP32
pub const SEED: &[u8; 12] = b"Bitcoin seed";

fn hmac_and_split(seed: &[u8], data: &[u8]) -> ([u8; 32], ChainCode) {
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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct XKeyInfo {
    /// The key depth in the HD tree
    depth: u8,
    /// The 4-byte Fingerprint of the parent
    parent: KeyFingerprint,
    /// The 4-byte derivation index of the key. If the most-significant byte is set, this key is
    /// hardened
    index: u32,
    /// The 32-byte chain code used to generate child keys
    chain_code: ChainCode,
    /// The key's stanadard output type preference
    hint: Hint,
}

/// A BIP32 Extended privkey. This key is genericized to accept any compatibile backend.
pub struct GenericXPriv<'a, T: Secp256k1Backend<'a>> {
    info: XKeyInfo,
    /// The associated secp256k1 key
    privkey: T::Privkey,
    #[doc(hidden)]
    backend: Option<&'a T>,
}

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
        Ok(GenericXPriv::new(
            0,
            parent,
            0,
            privkey,
            chain_code,
            hint.unwrap_or(Hint::SegWit),
            Some(backend),
        ))
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

    #[doc(hidden)]
    pub fn new(
        depth: u8,
        parent: KeyFingerprint,
        index: u32,
        privkey: T::Privkey,
        chain_code: ChainCode,
        hint: Hint,
        backend: Option<&'a T>,
    ) -> Self {
        Self {
            info: XKeyInfo {
                depth,
                parent,
                index,
                chain_code,
                hint,
            },
            privkey,
            backend,
        }
    }

    /// Return a `Pubkey` corresponding to the private key
    pub fn pubkey(&self) -> Result<T::Pubkey, Bip32Error> {
        Ok(self.backend()?.derive_pubkey(&self.privkey))
    }

    /// Return the secret key as an array
    pub fn secret_key(&self) -> [u8; 32] {
        self.privkey.privkey_array()
    }

    #[doc(hidden)]
    pub fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.backend.ok_or(Bip32Error::NoBackend)
    }

    /// Derive the corresponding xpub
    pub fn to_xpub(&self) -> Result<GenericXPub<'a, T>, Bip32Error> {
        Ok(GenericXPub {
            info: self.info,
            pubkey: self.pubkey()?,
            backend: self.backend,
        })
    }
}

impl<'a, T: Secp256k1Backend<'a>> XKey for GenericXPriv<'a, T> {
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error> {
        let digest = hash160(&self.pubkey()?.pubkey_array());
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&digest[..4]);
        Ok(buf.into())
    }

    fn depth(&self) -> u8 {
        self.info.depth
    }

    fn parent(&self) -> KeyFingerprint {
        self.info.parent
    }

    fn index(&self) -> u32 {
        self.info.index
    }

    fn chain_code(&self) -> ChainCode {
        self.info.chain_code
    }

    fn hint(&self) -> Hint {
        self.info.hint
    }

    fn derive_child(&self, index: u32) -> Result<GenericXPriv<'a, T>, Bip32Error> {
        let hardened = index >= BIP32_HARDEN;

        let mut data: Vec<u8> = vec![];
        if hardened {
            data.push(0);
            data.extend(&self.secret_key());
            data.extend(&index.to_be_bytes());
        } else {
            data.extend(&self.pubkey()?.pubkey_array().to_vec());
            data.extend(&index.to_be_bytes());
        };

        let (tweak, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        let privkey = self.backend()?.tweak_privkey(&self.privkey, tweak)?;

        Ok(GenericXPriv {
            info: XKeyInfo {
                depth: self.depth() + 1,
                parent: self.fingerprint()?,
                index,
                chain_code,
                hint: self.hint(),
            },
            privkey,
            backend: self.backend,
        })
    }

    fn pubkey_bytes(&self) -> Result<[u8; 33], Bip32Error> {
        Ok(self.pubkey()?.pubkey_array())
    }
}

/// A BIP32 Extended pubkey. This key is genericized to accept any compatibile backend.
pub struct GenericXPub<'a, T: Secp256k1Backend<'a>> {
    info: XKeyInfo,
    /// The associated secp256k1 key
    pubkey: T::Pubkey,
    #[doc(hidden)]
    backend: Option<&'a T>,
}

impl<'a, T: Secp256k1Backend<'a>> std::convert::TryFrom<&GenericXPriv<'a, T>>
    for GenericXPub<'a, T>
{
    type Error = Bip32Error;

    fn try_from(k: &GenericXPriv<'a, T>) -> Result<Self, Bip32Error> {
        Ok(Self::new(
            k.depth(),
            k.parent(),
            k.index(),
            k.pubkey()?,
            k.chain_code(),
            k.hint(),
            k.backend().ok(),
        ))
    }
}

impl<'a, T: Secp256k1Backend<'a>> ScalarSerialize for GenericXPriv<'a, T> {
    fn privkey_array(&self) -> [u8; 32] {
        self.privkey.privkey_array()
    }
}

impl<'a, T: Secp256k1Backend<'a>> XKey for GenericXPub<'a, T> {
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error> {
        let digest = hash160(&self.pubkey.pubkey_array());
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&digest[..4]);
        Ok(buf.into())
    }

    fn depth(&self) -> u8 {
        self.info.depth
    }

    fn parent(&self) -> KeyFingerprint {
        self.info.parent
    }

    fn index(&self) -> u32 {
        self.info.index
    }

    fn chain_code(&self) -> ChainCode {
        self.info.chain_code
    }

    fn hint(&self) -> Hint {
        self.info.hint
    }

    fn pubkey_bytes(&self) -> Result<[u8; 33], Bip32Error> {
        Ok(self.pubkey_array())
    }

    fn derive_child(&self, index: u32) -> Result<GenericXPub<'a, T>, Bip32Error> {
        if index >= BIP32_HARDEN {
            return Err(Bip32Error::HardenedKey);
        }
        let mut data: Vec<u8> = self.pubkey_array().to_vec();
        data.extend(&index.to_be_bytes());

        let (offset, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        // TODO: check for point at infinity
        if offset > CURVE_ORDER {
            return self.derive_child(index + 1);
        }

        let pubkey = self.backend()?.tweak_pubkey(&self.pubkey, offset)?;

        Ok(Self {
            info: XKeyInfo {
                depth: self.depth() + 1,
                parent: self.fingerprint()?,
                index,
                chain_code,
                hint: self.hint(),
            },
            pubkey,
            backend: self.backend,
        })
    }
}

impl<'a, T: Secp256k1Backend<'a>> GenericXPub<'a, T> {
    #[doc(hidden)]
    pub fn new(
        depth: u8,
        parent: KeyFingerprint,
        index: u32,
        pubkey: T::Pubkey,
        chain_code: ChainCode,
        hint: Hint,
        backend: Option<&'a T>,
    ) -> Self {
        Self {
            info: XKeyInfo{
                depth,
                parent,
                index,
                chain_code,
                hint,
            },
            pubkey,
            backend,
        }
    }

    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.backend.ok_or(Bip32Error::NoBackend)
    }

    /// Derive an XPub from an xpriv
    pub fn from_xpriv(xpriv: &GenericXPriv<'a, T>) -> Result<GenericXPub<'a, T>, Bip32Error> {
        xpriv.to_xpub()
    }
}

impl<'a, T: Secp256k1Backend<'a>> Clone for GenericXPriv<'a, T> {
    fn clone(&self) -> Self {
        Self::new(
            self.depth(),
            self.parent(),
            self.index(),
            self.privkey.clone(),
            self.chain_code(),
            self.hint(),
            self.backend,
        )
    }
}

impl<'a, T: Secp256k1Backend<'a>> Clone for GenericXPub<'a, T> {
    fn clone(&self) -> Self {
        Self::new(
            self.depth(),
            self.parent(),
            self.index(),
            self.pubkey.clone(),
            self.chain_code(),
            self.hint(),
            self.backend,
        )
    }
}

impl<'a, T: Secp256k1Backend<'a>> std::cmp::PartialEq for GenericXPriv<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.depth() == other.depth()
            && self.parent() == other.parent()
            && self.index() == other.index()
            && self.privkey == other.privkey
            && self.chain_code() == other.chain_code()
    }
}

impl<'a, T: Secp256k1Backend<'a>> Eq for GenericXPriv<'a, T> {}

impl<'a, T: Secp256k1Backend<'a>> std::cmp::PartialEq for GenericXPub<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.depth() == other.depth()
            && self.parent() == other.parent()
            && self.index() == other.index()
            && self.pubkey == other.pubkey
            && self.chain_code() == other.chain_code()
    }
}

impl<'a, T: Secp256k1Backend<'a>> Eq for GenericXPub<'a, T> {}

impl<'a, T: Secp256k1Backend<'a>> std::fmt::Debug for GenericXPub<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let idx = format!(
            "{}{}",
            self.index() % BIP32_HARDEN,
            if self.index() > BIP32_HARDEN { "h" } else { "" }
        );
        f.debug_struct("XPub")
            .field(
                "fingerprint",
                &self.fingerprint().unwrap_or_else(|_| [0u8; 4].into()),
            )
            .field("parent", &self.parent())
            .field("index", &idx)
            .field("hint", &self.hint())
            .finish()
    }
}

impl<'a, T: Secp256k1Backend<'a>> std::fmt::Debug for GenericXPriv<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let idx = format!(
            "{}{}",
            self.index() % BIP32_HARDEN,
            if self.index() > BIP32_HARDEN { "h" } else { "" }
        );
        f.debug_struct("XPriv")
            .field(
                "fingerprint",
                &self.fingerprint().unwrap_or_else(|_| [0u8; 4].into()),
            )
            .field("parent", &self.parent())
            .field("index", &idx)
            .field("hint", &self.hint())
            .finish()
    }
}

impl<'a, T: Secp256k1Backend<'a>> SigningKey for GenericXPriv<'a, T> {
    type VerifyingKey = GenericXPub<'a, T>;
    type Signature = T::Signature;
    type RecoverableSignature = T::RecoverableSignature;

    /// Derive the corresponding pubkey
    fn to_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        self.to_xpub()
    }

    /// Sign a digest
    fn sign_digest(&self, digest: [u8; 32]) -> Result<Self::Signature, Bip32Error> {
        Ok(self.backend()?.sign_digest(&self.privkey, digest))
    }

    /// Sign a digest and produce a recovery ID
    fn sign_digest_recoverable(
        &self,
        message: [u8; 32],
    ) -> Result<Self::RecoverableSignature, Bip32Error> {
        Ok(self
            .backend()?
            .sign_digest_recoverable(&self.privkey, message))
    }
}

impl<'a, T: Secp256k1Backend<'a>> PointSerialize for GenericXPub<'a, T> {
    fn pubkey_array(&self) -> [u8; 33] {
        self.pubkey.pubkey_array()
    }

    fn pubkey_array_uncompressed(&self) -> [u8; 65] {
        self.pubkey.pubkey_array_uncompressed()
    }
}

impl<'a, T: Secp256k1Backend<'a>> VerifyingKey for GenericXPub<'a, T> {
    type SigningKey = GenericXPriv<'a, T>;
    type Signature = T::Signature;
    type RecoverableSignature = T::RecoverableSignature;

    /// Instantiate `Self` from the corresponding signing key
    fn from_signing_key(key: &Self::SigningKey) -> Result<Self, Bip32Error> {
        key.to_verifying_key()
    }

    /// Verify a signature on a digest
    fn verify_digest(&self, digest: [u8; 32], sig: &Self::Signature) -> Result<(), Bip32Error> {
        self.backend()?.verify_digest(&self.pubkey, digest, sig)
    }
}

/// A BIP32 Extended privkey using the library's compiled-in secp256k1 backend.
#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub type XPriv<'a> = GenericXPriv<'a, crate::backends::curve::Secp256k1<'a>>;

/// A BIP32 Extended pubkey using the library's compiled-in secp256k1 backend.
#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub type XPub<'a> = GenericXPub<'a, crate::backends::curve::Secp256k1<'a>>;
