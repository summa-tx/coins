use k256::ecdsa;

use coins_core::prelude::{Hash160, Hash160Digest, MarkedDigest};

use crate::{
    path::{DerivationPath, KeyDerivation},
    primitives::{Hint, XKeyInfo},
    xkeys::{Parent, XPriv, XPub, SEED},
    Bip32Error,
};

/// Derived keys are keys coupled with their derivation. We use this trait to
/// check ancestry relationships between keys.
pub trait DerivedKey {
    /// Return this key's derivation
    fn derivation(&self) -> &KeyDerivation;

    /// `true` if the keys share a root fingerprint, `false` otherwise. Note that on key
    /// fingerprints, which may collide accidentally, or be intentionally collided.
    fn same_root<K: DerivedKey>(&self, other: &K) -> bool {
        self.derivation().same_root(&other.derivation())
    }

    /// `true` if this key is a possible ancestor of the argument, `false` otherwise.
    ///
    /// Warning: this check is cheap, but imprecise. It simply compares the root fingerprints
    /// (which may collide) and checks that `self.path` is a prefix of `other.path`. This may be
    /// deliberately foold by an attacker. For a precise check, use
    /// `DerivedXPriv::is_private_ancestor_of()` or
    /// `DerivedXPub::is_public_ancestor_of()`
    fn is_possible_ancestor_of<K: DerivedKey>(&self, other: &K) -> bool {
        self.derivation()
            .is_possible_ancestor_of(&other.derivation())
    }

    /// Returns the path to the descendant, or `None` if the argument is definitely not a
    /// descendant.
    ///
    /// This is useful for determining the path to reach some descendant from some ancestor.
    fn path_to_descendant<K: DerivedKey>(&self, other: &K) -> Option<DerivationPath> {
        self.derivation().path_to_descendant(&other.derivation())
    }
}

/// An XPriv with its derivation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DerivedXPriv {
    xpriv: XPriv,
    derivation: KeyDerivation,
}

inherit_signer!(DerivedXPriv.xpriv);

impl AsRef<XPriv> for DerivedXPriv {
    fn as_ref(&self) -> &XPriv {
        &self.xpriv
    }
}

impl AsRef<XKeyInfo> for DerivedXPriv {
    fn as_ref(&self) -> &XKeyInfo {
        &self.xpriv.xkey_info
    }
}

impl AsRef<ecdsa::SigningKey> for DerivedXPriv {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.xpriv.key
    }
}

impl DerivedKey for DerivedXPriv {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

impl DerivedXPriv {
    /// Instantiate a derived XPub from the XPub and derivatin. This usually
    /// should not be called directly. Prefer deriving keys from parents.
    pub fn new(xpriv: XPriv, derivation: KeyDerivation) -> Self {
        Self { xpriv, derivation }
    }

    /// Check if this XPriv is the private ancestor of some other derived key.
    /// To check ancestry of another private key, derive its public key first
    pub fn is_private_ancestor_of(&self, other: &DerivedXPub) -> Result<bool, Bip32Error> {
        if let Some(path) = self.path_to_descendant(other) {
            let descendant = self.derive_path(&path)?;
            Ok(descendant.verify_key() == *other)
        } else {
            Ok(false)
        }
    }

    /// Generate a customized root node using the static backend
    pub fn root_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<DerivedXPriv, Bip32Error> {
        Self::custom_root_node(hmac_key, data, hint)
    }

    /// Generate a root node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn root_from_seed(data: &[u8], hint: Option<Hint>) -> Result<DerivedXPriv, Bip32Error> {
        Self::custom_root_from_seed(data, hint)
    }

    /// Instantiate a root node using a custom HMAC key.
    pub fn custom_root_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<DerivedXPriv, Bip32Error> {
        let xpriv = XPriv::custom_root_node(hmac_key, data, hint)?;

        let derivation = KeyDerivation {
            root: xpriv.fingerprint(),
            path: vec![].into(),
        };

        Ok(DerivedXPriv { xpriv, derivation })
    }

    /// Generate a root node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn custom_root_from_seed(
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<DerivedXPriv, Bip32Error> {
        Self::custom_root_node(SEED, data, hint)
    }

    /// Derive the corresponding xpub
    pub fn verify_key(&self) -> DerivedXPub {
        DerivedXPub {
            xpub: self.xpriv.verify_key(),
            derivation: self.derivation.clone(),
        }
    }
}

impl Parent for DerivedXPriv {
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpriv: self.xpriv.derive_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

/// An XPub with its derivation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct DerivedXPub {
    xpub: XPub,
    derivation: KeyDerivation,
}

inherit_verifier!(DerivedXPub.xpub);

impl AsRef<XPub> for DerivedXPub {
    fn as_ref(&self) -> &XPub {
        &self.xpub
    }
}

impl AsRef<XKeyInfo> for DerivedXPub {
    fn as_ref(&self) -> &XKeyInfo {
        &self.xpub.xkey_info
    }
}

impl AsRef<ecdsa::VerifyingKey> for DerivedXPub {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.xpub.key
    }
}

impl Parent for DerivedXPub {
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpub: self.xpub.derive_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

impl DerivedKey for DerivedXPub {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

impl DerivedXPub {
    /// Instantiate a derived XPub from the XPub and derivatin. This usually
    /// should not be called directly. Prefer deriving keys from parents.
    pub fn new(xpub: XPub, derivation: KeyDerivation) -> Self {
        Self { xpub, derivation }
    }

    /// Check if this XPriv is the private ancestor of some other derived key
    pub fn is_public_ancestor_of(&self, other: &DerivedXPub) -> Result<bool, Bip32Error> {
        if let Some(path) = self.path_to_descendant(other) {
            let descendant = self.derive_path(&path)?;
            Ok(descendant == *other)
        } else {
            Ok(false)
        }
    }
}

/// A Pubkey with its derivation. Primarily used by PSBT.
pub struct DerivedPubkey {
    key: ecdsa::VerifyingKey,
    derivation: KeyDerivation,
}

inherit_verifier!(DerivedPubkey.key);

impl DerivedKey for DerivedPubkey {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

impl AsRef<ecdsa::VerifyingKey> for DerivedPubkey {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.key
    }
}

impl DerivedPubkey {
    /// Instantiate a new `
    pub fn new(key: ecdsa::VerifyingKey, derivation: KeyDerivation) -> Self {
        Self { key, derivation }
    }

    /// Return the hash of the compressed (Sec1) pubkey.
    pub fn pubkey_hash160(&self) -> Hash160Digest {
        Hash160::digest_marked(&self.key.to_bytes())
    }
}
