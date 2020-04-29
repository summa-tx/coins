use crate::{
    CURVE_ORDER,
    curve::model::*,
    model::*,
    keys::{GenericPrivkey, GenericPubkey},
    xkeys::{hmac_and_split, SEED, GenericXPriv, GenericXPub, XKeyInfo},
    path::KeyDerivation,
    Bip32Error,
};

// Re-exports
#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub use self::keys::{DerivedPubkey, DerivedPrivkey, DerivedXPriv, DerivedXPub};

/// A Pubkey coupled with its derivation
#[derive(Clone, Debug, PartialEq)]
pub struct GenericDerivedPrivkey<'a, T: Secp256k1Backend<'a>> {
    /// The underlying Privkey
    pub privkey: GenericPrivkey<'a, T>,
    /// Its derivation
    pub derivation: KeyDerivation,
}

impl<'a, T: Secp256k1Backend<'a>> HasPrivkey<'a, T> for GenericDerivedPrivkey<'a, T> {
    fn privkey(&self) -> &T::Privkey {
        self.privkey.privkey()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasBackend<'a, T> for GenericDerivedPrivkey<'a, T> {
    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.privkey.backend()
    }
}

impl<'a, T: Secp256k1Backend<'a>> SigningKey<'a, T> for GenericDerivedPrivkey<'a, T> {
    /// The corresponding verifying key
    type VerifyingKey = GenericDerivedPubkey<'a, T>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        Ok(GenericDerivedPubkey {
            pubkey: self.privkey.derive_verifying_key()?,
            derivation: self.derivation.clone(),
        })
    }
}

impl<'a, T: Secp256k1Backend<'a>> DerivedKey for GenericDerivedPrivkey<'a, T> {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

/// A Pubkey coupled with its derivation
#[derive(Clone, Debug, PartialEq)]
pub struct GenericDerivedPubkey<'a, T: Secp256k1Backend<'a>> {
    /// The underlying Pubkey
    pub pubkey: GenericPubkey<'a, T>,
    /// Its derivation
    pub derivation: KeyDerivation,
}

impl<'a, T: Secp256k1Backend<'a>> HasPubkey<'a, T> for GenericDerivedPubkey<'a, T> {
    fn pubkey(&self) -> &T::Pubkey {
        self.pubkey.pubkey()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasBackend<'a, T> for GenericDerivedPubkey<'a, T> {
    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.pubkey.backend()
    }
}

impl<'a, T: Secp256k1Backend<'a>> VerifyingKey<'a, T> for GenericDerivedPubkey<'a, T> {
    type SigningKey = GenericDerivedPrivkey<'a, T>;
}

impl<'a, T: Secp256k1Backend<'a>> DerivedKey for GenericDerivedPubkey<'a, T> {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

/// An XPriv coupled with its derivation
#[derive(Clone, Debug, PartialEq)]
pub struct GenericDerivedXPriv<'a, T: Secp256k1Backend<'a>> {
    /// The underlying Privkey
    pub xpriv: GenericXPriv<'a, T>,
    /// Its derivation
    pub derivation: KeyDerivation,
}

impl<'a, T: Secp256k1Backend<'a>> GenericDerivedXPriv<'a, T> {
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
                backend: Some(backend)
            }
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
    pub fn to_derived_xpub(&self) -> Result<GenericDerivedXPub<'a, T>, Bip32Error> {
        Ok(GenericDerivedXPub {
            xpub: self.xpriv.derive_verifying_key()?,
            derivation: self.derivation.clone(),
        })
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasXKeyInfo for GenericDerivedXPriv<'a, T> {
    fn xkey_info(&self) -> &XKeyInfo {
        self.xpriv.xkey_info()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasPrivkey<'a, T> for GenericDerivedXPriv<'a, T> {
    fn privkey(&self) -> &T::Privkey {
        self.xpriv.privkey()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasBackend<'a, T> for GenericDerivedXPriv<'a, T> {
    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.xpriv.backend()
    }
}

impl<'a, T: Secp256k1Backend<'a>> SigningKey<'a, T> for GenericDerivedXPriv<'a, T> {
    /// The corresponding verifying key
    type VerifyingKey = GenericDerivedXPub<'a, T>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        self.to_derived_xpub()
    }
}

impl<'a, T: Secp256k1Backend<'a>> DerivedKey for GenericDerivedXPriv<'a, T> {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

impl<'a, T: Secp256k1Backend<'a>> DerivePrivateChild<'a, T> for GenericDerivedXPriv<'a, T> {
    fn derive_private_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpriv: self.xpriv.derive_private_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

/// An XPub coupled with its derivation
#[derive(Clone, Debug, PartialEq)]
pub struct GenericDerivedXPub<'a, T: Secp256k1Backend<'a>> {
    /// The underlying XPub
    pub xpub: GenericXPub<'a, T>,
    /// Its derivation
    pub derivation: KeyDerivation,
}

impl<'a, T: Secp256k1Backend<'a>> GenericDerivedXPub<'a, T> {
    /// Derive an XPub from an xpriv
    pub fn from_derived_xpriv(xpriv: &GenericDerivedXPriv<'a, T>) -> Result<GenericDerivedXPub<'a, T>, Bip32Error> {
        xpriv.to_derived_xpub()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasXKeyInfo for GenericDerivedXPub<'a, T> {
    fn xkey_info(&self) -> &XKeyInfo {
        &self.xpub.xkey_info()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasPubkey<'a, T> for GenericDerivedXPub<'a, T> {
    fn pubkey(&self) -> &T::Pubkey {
        self.xpub.pubkey()
    }
}

impl<'a, T: Secp256k1Backend<'a>> HasBackend<'a, T> for GenericDerivedXPub<'a, T> {
    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.xpub.backend()
    }
}

impl<'a, T: Secp256k1Backend<'a>> VerifyingKey<'a, T> for GenericDerivedXPub<'a, T> {
    type SigningKey = GenericDerivedXPriv<'a, T>;
}

impl<'a, T: Secp256k1Backend<'a>> DerivedKey for GenericDerivedXPub<'a, T> {
    fn derivation(&self) -> &KeyDerivation {
        &self.derivation
    }
}

impl<'a, T: Secp256k1Backend<'a>> DerivePublicChild<'a, T> for GenericDerivedXPub<'a, T> {
    fn derive_public_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpub: self.xpub.derive_public_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
#[doc(hidden)]
pub mod keys {
    use super::*;

    use crate::Secp256k1;

    /// A Privkey coupled with its (purported) derivation path
    pub type DerivedPrivkey<'a> = GenericDerivedPrivkey<'a, Secp256k1<'a>>;

    /// A Pubkey coupled with its (purported) derivation path
    pub type DerivedPubkey<'a> = GenericDerivedPubkey<'a, Secp256k1<'a>>;

    /// An XPriv coupled with its (purported) derivation path
    pub type DerivedXPriv<'a> = GenericDerivedXPriv<'a, Secp256k1<'a>>;

    /// An XPub coupled with its (purported) derivation path
    pub type DerivedXPub<'a> = GenericDerivedXPub<'a, Secp256k1<'a>>;
}
