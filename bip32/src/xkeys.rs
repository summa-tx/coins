use secp256k1::{self, Secp256k1};

use crate::{
    Bip32Error,
    hd::{hmac_and_split},
    keys::{Privkey, Pubkey, SigningKey, VerifyingKey}
};

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
    fn fingerprint(&self) -> KeyFingerprint;
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

/// A 32-byte chain code
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct ChainCode(pub [u8; 32]);

/// A BIP32 Extended privkey
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct XPriv {
    /// The key depth in the HD tree
    depth: u8,
    /// The 4-byte Fingerprint of the parent
    parent: KeyFingerprint,
    /// The 4-byte derivation index of the key. If the most-significant byte is set, this key is
    /// hardened
    index: u32,
    /// The associated secp256k1 key
    privkey: Privkey,
    /// The 32-byte chain code used to generate child keys
    chain_code: ChainCode,
    /// The key's stanadard output type preference
    hint: Hint,
}

impl XPriv {
    /// Instantiate a new XPriv
    pub fn new(depth: u8, parent: KeyFingerprint, index: u32, privkey: Privkey, chain_code: ChainCode, hint: Hint,) -> Self {
        Self{
            depth,
            parent,
            index,
            privkey,
            chain_code,
            hint,
        }
    }

    /// Return a `Pubkey` corresponding to the private key
    pub fn pubkey<C>(&self, context: Option<&Secp256k1<C>>) -> Pubkey
    where
        C: secp256k1::Signing
    {
        Pubkey::from_signing_key(context, &self.privkey)
    }

    /// Return a clone of the underlying `Privkey`
    pub fn privkey(&self) -> Privkey {
        self.privkey.clone()
    }

    /// Return the secret key as an array
    pub fn secret_key(&self) -> [u8; 32] {
        self.privkey.serialize()
    }

    /// Derive a child `XPriv`
    pub fn derive_child<C>(&self, context: Option<&Secp256k1<C>>, index: u32) -> Result<Self, Bip32Error>
    where
        C: secp256k1::Verification + secp256k1::Signing
    {
        let hardened = index >= 2_u32.pow(31);
        let data = if hardened {
            let mut v: Vec<u8> = vec![0];
            v.extend(&self.secret_key());
            v.extend(&index.to_be_bytes());
            v
        } else {
            let mut v: Vec<u8> = vec![0];
            v.extend(&self.pubkey(context).serialize().to_vec());
            v.extend(&index.to_be_bytes());
            v
        };

        let (left, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        let privkey = self.privkey.tweak_add(left)?;

        Ok(XPriv{
            depth: self.depth() + 1,
            parent: self.fingerprint(),
            index,
            chain_code,
            privkey,
            hint: self.hint(),
        })
    }
}

impl SigningKey for XPriv {
    fn tweak_add(&self, _other: [u8; 32]) -> Result<Self, Bip32Error> {
        Err(Bip32Error::BadTweak)
    }

    fn sign_digest<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32]) -> secp256k1::Signature
    where
        C: secp256k1::Signing
    {
        self.privkey.sign_digest(context, digest)
    }

    fn sign_digest_recoverable<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32]) -> secp256k1::recovery::RecoverableSignature
    where
        C: secp256k1::Signing
    {
        self.privkey.sign_digest_recoverable(context, digest)
    }
}

impl XKey for XPriv {
    fn fingerprint(&self) -> KeyFingerprint {
        unimplemented!()
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
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct XPub {
    /// The key depth in the HD tree
    depth: u8,
    /// The 4-byte Fingerprint of the parent
    parent: KeyFingerprint,
    /// The 4-byte derivation index of the key. If the most-significant byte is set, this key is
    /// hardened
    index: u32,
    /// The associated secp256k1 key
    pubkey: Pubkey,
    /// The 32-byte chain code used to generate child keys
    chain_code: ChainCode,
    /// The key's stanadard output type preference
    hint: Hint,
}


impl XKey for XPub {
    fn fingerprint(&self) -> KeyFingerprint {
        unimplemented!()
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


impl XPub {
    /// Instantiate a new XPub
    pub fn new(depth: u8, parent: KeyFingerprint, index: u32, pubkey: Pubkey, chain_code: ChainCode, hint: Hint,) -> Self {
        Self{
            depth,
            parent,
            index,
            pubkey,
            chain_code,
            hint,
        }
    }

    /// Derive a child `XPub`
    pub fn derive_child<C>(&self, context: Option<&Secp256k1<C>>, index: u32) -> Result<XPub, Bip32Error>
    where
        C: secp256k1::Verification
    {
        if index >= 2u32.pow(31) {
            return Err(Bip32Error::HardenedKey)
        }
        let mut data: Vec<u8> = self.compressed_pubkey().to_vec();
        data.extend(&index.to_be_bytes());

        let (offset, chain_code) = hmac_and_split(&self.chain_code().0, &data);
        // TODO: check for point at infinity
        if offset > secp256k1::constants::CURVE_ORDER {
            return self.derive_child(context, index + 1);
        }

        let pubkey = self.pubkey.tweak_add(context, offset)?;

        Ok(Self{
            depth: self.depth() + 1,
            parent: self.fingerprint(),
            index,
            pubkey,
            chain_code,
            hint: self.hint(),
        })
    }

    /// Serialize the uncompressed pubkey
    pub fn uncompressed_pubkey(&self) -> [u8; 65] {
        self.pubkey.serialize_uncompressed()
    }

    /// Serialize the compressed pubkey
    pub fn compressed_pubkey(&self) -> [u8; 33] {
        self.pubkey.serialize()
    }
}

impl VerifyingKey for XPub {
    type SigningKey = XPriv;

    fn tweak_add<C>(&self, _context: Option<&Secp256k1<C>>, _tweak: [u8; 32]) -> Result<Self, Bip32Error>
    where
        C: secp256k1::Verification
    {
        Err(Bip32Error::BadTweak)
    }

    fn from_signing_key<C>(context: Option<&Secp256k1<C>>, key: &Self::SigningKey) -> Self
    where
        C: secp256k1::Signing
    {
        Self{
            depth: key.depth(),
            parent: key.parent(),
            index: key.index(),
            pubkey: Pubkey::from_signing_key(context, &key.privkey()),
            chain_code: key.chain_code(),
            hint: key.hint(),
        }
    }

    fn verify_digest<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32], sig: &secp256k1::Signature) -> Result<(), Bip32Error>
    where
        C: secp256k1::Verification
    {
        self.pubkey.verify_digest(context, digest, sig)
    }
}
