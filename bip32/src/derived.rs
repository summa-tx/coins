use crate::{
    curve::model::{ScalarDeserialize, Secp256k1Backend},
    keys::{GenericPrivkey, GenericPubkey},
    model::*,
    path::KeyDerivation,
    primitives::{Hint, KeyFingerprint, XKeyInfo},
    xkeys::{hmac_and_split, GenericXPriv, GenericXPub, SEED},
    Bip32Error, CURVE_ORDER,
};

// Re-exports
#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub use self::keys::{DerivedPrivkey, DerivedPubkey, DerivedXPriv, DerivedXPub};

make_derived_key!(
    /// A Privkey coupled with its derivation
    GenericPrivkey,
    GenericDerivedPrivkey.privkey
);
inherit_has_privkey!(GenericDerivedPrivkey.privkey);
inherit_backend!(GenericDerivedPrivkey.privkey);

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

make_derived_key!(
    /// A Pubkey coupled with its derivation
    GenericPubkey,
    GenericDerivedPubkey.pubkey
);
inherit_has_pubkey!(GenericDerivedPubkey.pubkey);
inherit_backend!(GenericDerivedPubkey.pubkey);

impl<'a, T: Secp256k1Backend<'a>> VerifyingKey<'a, T> for GenericDerivedPubkey<'a, T> {
    type SigningKey = GenericDerivedPrivkey<'a, T>;
}

make_derived_key!(
    /// An XPriv coupled with its derivation
    GenericXPriv,
    GenericDerivedXPriv.xpriv
);
inherit_has_privkey!(GenericDerivedXPriv.xpriv);
inherit_backend!(GenericDerivedXPriv.xpriv);
inherit_has_xkeyinfo!(GenericDerivedXPriv.xpriv);

impl<'a, T: Secp256k1Backend<'a>> GenericDerivedXPriv<'a, T> {
    /// Instantiate a master node using a custom HMAC key.
    pub fn custom_master_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
        backend: &'a T,
    ) -> Result<GenericDerivedXPriv<'a, T>, Bip32Error> {
        if data.len() < 16 {
            return Err(Bip32Error::SeedTooShort);
        }
        let parent = KeyFingerprint([0u8; 4]);
        let (key, chain_code) = hmac_and_split(hmac_key, data);
        if key == [0u8; 32] || key > CURVE_ORDER {
            return Err(Bip32Error::InvalidKey);
        }
        let key = T::Privkey::from_privkey_array(key)?;

        let info = XKeyInfo {
            depth: 0,
            parent,
            index: 0,
            chain_code,
            hint: hint.unwrap_or(Hint::SegWit),
        };

        let privkey = GenericPrivkey {
            key,
            backend: Some(backend),
        };

        let derivation = KeyDerivation {
            root: privkey.derive_fingerprint()?,
            path: vec![].into()
        };

        Ok(GenericDerivedXPriv {
            xpriv: GenericXPriv {
                info,
                privkey,
            },
            derivation,
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
    ) -> Result<GenericDerivedXPriv<'a, T>, Bip32Error> {
        Self::custom_master_node(SEED, data, hint, backend)
    }

    /// Derive the corresponding xpub
    pub fn to_derived_xpub(&self) -> Result<GenericDerivedXPub<'a, T>, Bip32Error> {
        Ok(GenericDerivedXPub {
            xpub: self.xpriv.derive_verifying_key()?,
            derivation: self.derivation.clone(),
        })
    }

    /// Check if this XPriv is the private ancestor of some other derived key
    pub fn is_private_ancestor_of<D: DerivedKey + HasPubkey<'a, T>>(
        &self,
        other: &D,
    ) -> Result<bool, Bip32Error> {
        if let Some(path) = self.path_to_descendant(other) {
            let descendant = self.derive_private_path(&path)?;
            let descendant_pk_bytes = descendant.derive_pubkey()?;
            Ok(&descendant_pk_bytes == other.pubkey())
        } else {
            Ok(false)
        }
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

impl<'a, T: Secp256k1Backend<'a>> DerivePrivateChild<'a, T> for GenericDerivedXPriv<'a, T> {
    fn derive_private_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpriv: self.xpriv.derive_private_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

make_derived_key!(
    /// An XPub coupled with its derivation
    GenericXPub,
    GenericDerivedXPub.xpub
);
inherit_has_pubkey!(GenericDerivedXPub.xpub);
inherit_backend!(GenericDerivedXPub.xpub);
inherit_has_xkeyinfo!(GenericDerivedXPub.xpub);

impl<'a, T: Secp256k1Backend<'a>> GenericDerivedXPub<'a, T> {
    /// Derive an XPub from an xpriv
    pub fn from_derived_xpriv(
        xpriv: &GenericDerivedXPriv<'a, T>,
    ) -> Result<GenericDerivedXPub<'a, T>, Bip32Error> {
        xpriv.to_derived_xpub()
    }

    /// Check if this XPriv is the private ancestor of some other derived key
    pub fn is_public_ancestor_of<D: DerivedKey + HasPubkey<'a, T>>(
        &self,
        other: &D,
    ) -> Result<bool, Bip32Error> {
        if let Some(path) = self.path_to_descendant(other) {
            let descendant = self.derive_public_path(&path)?;
            Ok(descendant.pubkey() == other.pubkey())
        } else {
            Ok(false)
        }
    }
}

impl<'a, T: Secp256k1Backend<'a>> VerifyingKey<'a, T> for GenericDerivedXPub<'a, T> {
    type SigningKey = GenericDerivedXPriv<'a, T>;
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        curve::*,
        enc::{Encoder, MainnetEncoder},
        primitives::*,
        path::DerivationPath,
        BIP32_HARDEN,
    };

    use hex;

    struct KeyDeriv<'a> {
        pub path: &'a [u32],
    }

    fn validate_descendant<'a>(d: &KeyDeriv, m: &DerivedXPriv<'a>) {
        let path: DerivationPath = d.path.into();

        let m_pub = m.derive_verifying_key().unwrap();

        let xpriv = m.derive_private_path(&path).unwrap();
        let xpub = xpriv.derive_verifying_key().unwrap();
        assert!(m.same_root(&xpriv));
        assert!(m.same_root(&xpub));
        assert!(m.is_possible_ancestor_of(&xpriv));
        assert!(m.is_possible_ancestor_of(&xpub));

        let result = m.is_private_ancestor_of(&xpub).expect("should work");

        if !result {
            assert!(false, "failed validate_descendant is_private_ancestor_of");
        }

        let result = m_pub.is_public_ancestor_of(&xpub);

        match result {
            Ok(true) => {},
            Ok(false) => assert!(false, "failed validate_descendant is_public_ancestor_of"),
            Err(_) => {
                let path: crate::path::DerivationPath = d.path.into();
                assert!(path.last_hardened().1.is_some(), "is_public_ancestor_of failed for unhardened path")
            }
        }

        let derived_path = m.path_to_descendant(&xpriv).expect("expected a path to descendant");
        assert_eq!(&path, &derived_path, "derived path is not as expected");
    }

    #[test]
    fn bip32_vector_1() {
        let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let backend = Secp256k1::init();

        let xpriv = DerivedXPriv::root_from_seed(&seed, Some(Hint::Legacy), &backend).unwrap();

        let descendants = [
            KeyDeriv {
                path: &[0 + BIP32_HARDEN],
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1],
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN],
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2],
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2, 1000000000],
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_2() {
        let seed = hex::decode(&"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let backend = Secp256k1::init();

        let xpriv = DerivedXPriv::root_from_seed(&seed, Some(Hint::Legacy), &backend).unwrap();

        let descendants = [
            KeyDeriv {
                path: &[0],
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN],
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1],
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1, 2147483646 + BIP32_HARDEN],
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1, 2147483646 + BIP32_HARDEN, 2],
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_3() {
        let seed = hex::decode(&"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
        let backend = Secp256k1::init();

        let xpriv = DerivedXPriv::root_from_seed(&seed, Some(Hint::Legacy), &backend).unwrap();

        let descendants = [
            KeyDeriv {
                path: &[0 + BIP32_HARDEN],
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn it_can_sign_and_verify() {
        let digest = [1u8; 32];
        let backend = Secp256k1::init();
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();

        let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(&backend)).unwrap();

        let child = xpriv.derive_private_child(33).unwrap();
        let sig = child.sign_digest(digest).unwrap();

        let child_xpub = child.derive_verifying_key().unwrap();
        child_xpub.verify_digest(digest, &sig).unwrap();
    }
}
