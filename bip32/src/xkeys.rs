use sha2::{Sha512};
use bitcoin_spv::btcspv::{hash160};
use hmac::{Hmac, Mac};

use crate::{
    Bip32Error,
    backend::{
        PointSerialize,
        ScalarSerialize,
        Secp256k1Backend,
    },
};

type HmacSha512 = Hmac<Sha512>;

const SEED: &[u8; 12] = b"Bitcoin seed";

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

/// We treat the xpub/ypub/zpub convention as a hint
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Hint {
    /// Standard Bip32 hint
    Legacy,
    /// Bip32 + Bip49 hint for Witness-via-P2SH
    Compatibility,
    /// Bip32 + Bip84 hint for Native SegWit
    SegWit,
}

/// Extended Key common features
pub trait XKey: std::marker::Sized {
    /// Calculate and return the key fingerprint
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error>;
    /// Get the key's depth
    fn depth(&self) -> u8;
    /// Set the key's depth
    fn set_depth(&mut self, depth: u8);
    /// Get the key's parent
    fn parent(&self) -> KeyFingerprint;
    /// Set the key's parent
    fn set_parent(&mut self, parent: KeyFingerprint);
    /// Get the key's index
    fn index(&self) -> u32;
    /// Set the key's index
    fn set_index(&mut self, index: u32);
    /// Get the key's chain_code
    fn chain_code(&self) -> ChainCode;
    /// Set the key's chain_code
    fn set_chain_code(&mut self, chain_code: ChainCode);
    /// Get the key's hint
    fn hint(&self) -> Hint;
    /// Set the key's hint
    fn set_hint(&mut self, hint: Hint);
}

/// A 4-byte key fingerprint
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct KeyFingerprint(pub [u8; 4]);

impl From<[u8; 4]> for KeyFingerprint {
    fn from(v: [u8; 4]) -> Self {
        Self(v)
    }
}

/// A 32-byte chain code
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct ChainCode(pub [u8; 32]);

impl From<[u8; 32]> for ChainCode {
    fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}
/// A BIP32 Extended privkey
#[derive(Clone)]
pub struct XPriv<'a, T: Secp256k1Backend> {
    /// The key depth in the HD tree
    depth: u8,
    /// The 4-byte Fingerprint of the parent
    parent: KeyFingerprint,
    /// The 4-byte derivation index of the key. If the most-significant byte is set, this key is
    /// hardened
    index: u32,
    /// The associated secp256k1 key
    privkey: T::Privkey,
    /// The 32-byte chain code used to generate child keys
    chain_code: ChainCode,
    /// The key's stanadard output type preference
    hint: Hint,
    #[doc(hidden)]
    backend: Option<&'a T>,
}

impl<'a, T: Secp256k1Backend> XPriv<'a, T> {
    /// Generate a master node from a seed
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn generate_master_node(data: &[u8], hint: Option<Hint>, backend: &'a T) -> Result<XPriv<'a, T>, Bip32Error> {
        if data.len() < 16 {
            return Err(Bip32Error::SeedTooShort);
        }
        let parent = KeyFingerprint([0u8; 4]);
        let (key, chain_code) = hmac_and_split(SEED, data);
        if key == [0u8; 32] || key > secp256k1::constants::CURVE_ORDER {
            return Err(Bip32Error::InvalidKey);
        }
        let privkey = T::Privkey::from_array(key);
        Ok(XPriv::new(0, parent, 0, privkey, chain_code, hint.unwrap_or(Hint::SegWit), Some (backend)))
    }

    /// Instantiate a new XPriv
    pub fn new(depth: u8, parent: KeyFingerprint, index: u32, privkey: T::Privkey, chain_code: ChainCode, hint: Hint, backend: Option<&'a T>) -> Self {
        Self{
            depth,
            parent,
            index,
            privkey,
            chain_code,
            hint,
            backend,
        }
    }

    /// Return a `Pubkey` corresponding to the private key
    pub fn pubkey(&self) -> Result<T::Pubkey, Bip32Error> {
        Ok(self.backend()?.derive_pubkey(&self.privkey))
    }

    /// Return the secret key as an array
    pub fn secret_key(&self) -> [u8; 32] {
        self.privkey.to_array()
    }

    /// Derive a child `XPriv`
    pub fn derive_child(&self, index: u32) -> Result<XPriv<T>, Bip32Error>{
        let hardened = index >= 2_u32.pow(31);
        let data = if hardened {
            let mut v: Vec<u8> = vec![0];
            v.extend(&self.secret_key());
            v.extend(&index.to_be_bytes());
            v
        } else {
            let mut v: Vec<u8> = vec![0];
            v.extend(&self.pubkey()?.to_array().to_vec());
            v.extend(&index.to_be_bytes());
            v
        };

        let (left, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        let privkey = self.backend()?.tweak_privkey(&self.privkey, left)?;

        Ok(XPriv{
            depth: self.depth() + 1,
            parent: self.fingerprint()?,
            index,
            chain_code,
            privkey,
            hint: self.hint(),
            backend: self.backend
        })
    }

    #[doc(hidden)]
    pub fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.backend.ok_or(Bip32Error::NoBackend)
    }
}

impl<'a, T: Secp256k1Backend> XKey for XPriv<'a, T> {
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&hash160(&self.pubkey()?.to_array())[..4]);
        Ok(buf.into())
    }

    fn depth(&self) -> u8 {
        self.depth
    }
    fn set_depth(&mut self, depth: u8) {
        self.depth = depth
    }
    fn parent(&self) -> KeyFingerprint {
        self.parent
    }
    fn set_parent(&mut self, parent: KeyFingerprint) {
        self.parent = parent
    }
    fn index(&self) -> u32 {
        self.index
    }
    fn set_index(&mut self, index: u32) {
        self.index = index
    }
    fn chain_code(&self) -> ChainCode {
        self.chain_code
    }
    fn set_chain_code(&mut self, chain_code: ChainCode) {
        self.chain_code = chain_code
    }
    fn hint(&self) -> Hint {
        self.hint
    }
    fn set_hint(&mut self, hint: Hint) {
        self.hint = hint
    }
}

/// A BIP32 Extended pubkey
#[derive(Clone)]
pub struct XPub<'a, T: Secp256k1Backend> {
    /// The key depth in the HD tree
    depth: u8,
    /// The 4-byte Fingerprint of the parent
    parent: KeyFingerprint,
    /// The 4-byte derivation index of the key. If the most-significant byte is set, this key is
    /// hardened
    index: u32,
    /// The associated secp256k1 key
    pubkey: T::Pubkey,
    /// The 32-byte chain code used to generate child keys
    chain_code: ChainCode,
    /// The key's stanadard output type preference
    hint: Hint,
    #[doc(hidden)]
    backend: Option<&'a T>,
}

impl<'a, T: Secp256k1Backend> std::convert::TryFrom<&XPriv<'a, T>> for XPub<'a, T> {
    type Error = Bip32Error;

    fn try_from(k: &XPriv<'a, T>) -> Result<Self, Bip32Error> {
        Ok(Self::new(
            k.depth(),
            k.parent(),
            k.index(),
            k.pubkey()?,
            k.chain_code(),
            k.hint(),
            k.backend().ok()
        ))
    }
}

impl<'a, T: Secp256k1Backend> XKey for XPub<'a, T> {
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&hash160(&self.pubkey.to_array())[..4]);
        Ok(buf.into())
    }

    fn depth(&self) -> u8 {
        self.depth
    }
    fn set_depth(&mut self, depth: u8) {
        self.depth = depth
    }
    fn parent(&self) -> KeyFingerprint {
        self.parent
    }
    fn set_parent(&mut self, parent: KeyFingerprint) {
        self.parent = parent
    }
    fn index(&self) -> u32 {
        self.index
    }
    fn set_index(&mut self, index: u32) {
        self.index = index
    }
    fn chain_code(&self) -> ChainCode {
        self.chain_code
    }
    fn set_chain_code(&mut self, chain_code: ChainCode) {
        self.chain_code = chain_code
    }
    fn hint(&self) -> Hint {
        self.hint
    }
    fn set_hint(&mut self, hint: Hint) {
        self.hint = hint
    }
}

impl<'a, T: Secp256k1Backend> XPub<'a, T> {
    /// Instantiate a new XPub
    pub fn new(depth: u8, parent: KeyFingerprint, index: u32, pubkey: T::Pubkey, chain_code: ChainCode, hint: Hint, backend: Option<&'a T>) -> Self {
        Self{
            depth,
            parent,
            index,
            pubkey,
            chain_code,
            hint,
            backend,
        }
    }

    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.backend.ok_or(Bip32Error::NoBackend)
    }

    /// Derive a child `XPub`
    pub fn derive_child(&self, index: u32) -> Result<XPub<T>, Bip32Error> {
        if index >= 2u32.pow(31) {
            return Err(Bip32Error::HardenedKey)
        }
        let mut data: Vec<u8> = self.compressed_pubkey().to_vec();
        data.extend(&index.to_be_bytes());

        let (offset, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        // TODO: check for point at infinity
        if offset > secp256k1::constants::CURVE_ORDER {
            return self.derive_child(index + 1);
        }

        let pubkey = self.backend()?.tweak_pubkey(&self.pubkey, offset)?;

        Ok(Self{
            depth: self.depth() + 1,
            parent: self.fingerprint()?,
            index,
            pubkey,
            chain_code,
            hint: self.hint(),
            backend: self.backend,
        })
    }

    /// Serialize the uncompressed pubkey
    pub fn uncompressed_pubkey(&self) -> [u8; 65] {
        self.pubkey.to_array_uncompressed()
    }

    /// Serialize the compressed pubkey
    pub fn compressed_pubkey(&self) -> [u8; 33] {
        self.pubkey.to_array()
    }

    /// Serialize the compressed pubkey
    pub fn raw_pubkey(&self) -> [u8; 64] {
        self.pubkey.to_array_raw()
    }
}

impl<'a, T: Secp256k1Backend> std::cmp::PartialEq for XPriv<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.depth() == other.depth()
        && self.parent() == other.parent()
        && self.index() == other.index()
        && self.privkey == other.privkey
        && self.chain_code() == other.chain_code()
    }
}

impl<'a, T: Secp256k1Backend> Eq for XPriv<'a, T> {}

impl<'a, T: Secp256k1Backend> std::cmp::PartialEq for XPub<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.depth() == other.depth()
        && self.parent() == other.parent()
        && self.index() == other.index()
        && self.pubkey == other.pubkey
        && self.chain_code() == other.chain_code()
    }
}

impl<'a, T: Secp256k1Backend> Eq for XPub<'a, T> {}

impl<'a, T: Secp256k1Backend> std::fmt::Debug for XPub<'a, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XPub")
         .field("fingerprint", &self.fingerprint().unwrap_or_else(|_| [0u8; 4].into()))
         .finish()
    }
}

impl<'a, T: Secp256k1Backend> std::fmt::Debug for XPriv<'a, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XPriv")
         .field("fingerprint", &self.fingerprint().unwrap_or_else(|_| [0u8; 4].into()))
         .finish()
    }
}