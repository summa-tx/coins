use crate::{
    curve::model::Secp256k1Backend,
    keys::{GenericPrivkey, GenericPubkey},
    model::*,
    path::KeyDerivation,
    primitives::Hint,
    xkeys::{GenericXPriv, GenericXPub, SEED},
    Bip32Error,
};

/// A GenericDerivedPrivkey using the compiled-in default backend, coupled with its (purported)
/// derivation path.
///
/// For interface documentation see the page for
/// [GenericDerivedPrivkey](struct.GenericDerivedPrivkey.html).
pub type DerivedPrivkey = GenericDerivedPrivkey<'static, crate::curve::Secp256k1<'static>>;

/// A GenericDerivedPubkey using the compiled-in default backend, coupled with its (purported)
/// derivation path.
///
/// For interface documentation see the page for
/// [GenericDerivedPubkey](struct.GenericDerivedPubkey.html).
pub type DerivedPubkey = GenericDerivedPubkey<'static, crate::curve::Secp256k1<'static>>;

/// A GenericDerivedXPriv using the compiled-in default backend, coupled with its (purported)
/// derivation path.
///
/// For interface documentation see the page for
///  [GenericDerivedXPriv](struct.GenericDerivedXPriv.html).
pub type DerivedXPriv = GenericDerivedXPriv<'static, crate::curve::Secp256k1<'static>>;

/// A GenericDerivedXPub using the compiled-in default backend, coupled with its (purported)
/// derivation path.
///
/// For interface documentation see the page for
///  [GenericDerivedXPub](struct.GenericDerivedXPub.html).
pub type DerivedXPub = GenericDerivedXPub<'static, crate::curve::Secp256k1<'static>>;

make_derived_key!(
    /// A `Privkey` coupled with its (purported) derivation path. Generally this struct
    /// should be used over Privkey wherever possible, in order to preserve information ancestry
    /// relationship information.
    ///
    /// Warning: derivation paths from untrusted sources may be faulty. Make sure to check
    /// ancestry using the `DerivedKey` trait methods.
    GenericPrivkey,
    GenericDerivedPrivkey.privkey
);
inherit_has_privkey!(GenericDerivedPrivkey.privkey);
inherit_backend!(GenericDerivedPrivkey.privkey);

impl<'a, T: Secp256k1Backend> SigningKey<'a, T> for GenericDerivedPrivkey<'a, T> {
    type VerifyingKey = GenericDerivedPubkey<'a, T>;

    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        Ok(GenericDerivedPubkey {
            pubkey: self.privkey.derive_verifying_key()?,
            derivation: self.derivation.clone(),
        })
    }
}

make_derived_key!(
    /// A `GenericPubkey` coupled with its (purported) derivation path. Generally this struct
    /// should be used over Pubkey wherever possible, in order to preserve information ancestry
    /// relationship information.
    ///
    /// Warning: derivation paths from untrusted sources may be faulty. Make sure to check
    /// ancestry using the `DerivedKey` trait methods.
    GenericPubkey,
    GenericDerivedPubkey.pubkey
);
inherit_has_pubkey!(GenericDerivedPubkey.pubkey);
inherit_backend!(GenericDerivedPubkey.pubkey);

impl<'a, T: Secp256k1Backend> VerifyingKey<'a, T> for GenericDerivedPubkey<'a, T> {
    type SigningKey = GenericDerivedPrivkey<'a, T>;
}

make_derived_key!(
    /// A `GenericXPriv` coupled with its (purported) derivation path. Generally this struct
    /// should be used over XPriv wherever possible, in order to preserve information ancestry
    /// relationship information.
    ///
    /// Warning: derivation paths from untrusted sources may be faulty. Make sure to check
    /// ancestry using the `DerivedKey` trait methods.
    GenericXPriv,
    GenericDerivedXPriv.xpriv
);
inherit_has_privkey!(GenericDerivedXPriv.xpriv);
inherit_backend!(GenericDerivedXPriv.xpriv);
inherit_has_xkeyinfo!(GenericDerivedXPriv.xpriv);

impl DerivedXPriv {
    /// Generate a customized master node using the static backend
    pub fn master_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<DerivedXPriv, Bip32Error> {
        Self::custom_master_node(hmac_key, data, hint, crate::curve::Secp256k1::static_ref())
    }

    /// Generate a master node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn root_from_seed(data: &[u8], hint: Option<Hint>) -> Result<DerivedXPriv, Bip32Error> {
        Self::custom_root_from_seed(data, hint, crate::curve::Secp256k1::static_ref())
    }
}

impl<'a, T: Secp256k1Backend> GenericDerivedXPriv<'a, T> {
    /// Instantiate a master node using a custom HMAC key.
    pub fn custom_master_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
        backend: &'a T,
    ) -> Result<GenericDerivedXPriv<'a, T>, Bip32Error> {
        let xpriv = GenericXPriv::custom_master_node(hmac_key, data, hint, backend)?;

        let derivation = KeyDerivation {
            root: xpriv.derive_fingerprint()?,
            path: vec![].into(),
        };

        Ok(GenericDerivedXPriv { xpriv, derivation })
    }

    /// Generate a master node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn custom_root_from_seed(
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

impl<'a, T: Secp256k1Backend> SigningKey<'a, T> for GenericDerivedXPriv<'a, T> {
    /// The corresponding verifying key
    type VerifyingKey = GenericDerivedXPub<'a, T>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        self.to_derived_xpub()
    }
}

impl<'a, T: Secp256k1Backend> DerivePrivateChild<'a, T> for GenericDerivedXPriv<'a, T> {
    fn derive_private_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpriv: self.xpriv.derive_private_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

make_derived_key!(
    /// A `GenericXPub` coupled with its (purported) derivation path. Generally this struct
    /// should be used over XPub wherever possible, in order to preserve information ancestry
    /// relationship information.
    ///
    /// Warning: derivation paths from untrusted sources may be faulty. Make sure to check
    /// ancestry using the `DerivedKey` trait methods.
    GenericXPub,
    GenericDerivedXPub.xpub
);
inherit_has_pubkey!(GenericDerivedXPub.xpub);
inherit_backend!(GenericDerivedXPub.xpub);
inherit_has_xkeyinfo!(GenericDerivedXPub.xpub);

impl<'a, T: Secp256k1Backend> GenericDerivedXPub<'a, T> {
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

impl<'a, T: Secp256k1Backend> VerifyingKey<'a, T> for GenericDerivedXPub<'a, T> {
    type SigningKey = GenericDerivedXPriv<'a, T>;
}

impl<'a, T: Secp256k1Backend> DerivePublicChild<'a, T> for GenericDerivedXPub<'a, T> {
    fn derive_public_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            xpub: self.xpub.derive_public_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        curve::*,
        enc::{MainnetEncoder, XKeyEncoder},
        path::DerivationPath,
        primitives::*,
        BIP32_HARDEN,
    };

    use hex;

    struct KeyDeriv<'a> {
        pub path: &'a [u32],
    }

    fn validate_descendant(d: &KeyDeriv, m: &DerivedXPriv) {
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
            Ok(true) => {}
            Ok(false) => assert!(false, "failed validate_descendant is_public_ancestor_of"),
            Err(_) => {
                let path: crate::path::DerivationPath = d.path.into();
                assert!(
                    path.last_hardened().1.is_some(),
                    "is_public_ancestor_of failed for unhardened path"
                )
            }
        }

        let derived_path = m
            .path_to_descendant(&xpriv)
            .expect("expected a path to descendant");
        assert_eq!(&path, &derived_path, "derived path is not as expected");
    }

    #[test]
    fn bip32_vector_1() {
        let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let xpriv = DerivedXPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();

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

        let xpriv = DerivedXPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();

        let descendants = [
            KeyDeriv { path: &[0] },
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
                path: &[
                    0,
                    2147483647 + BIP32_HARDEN,
                    1,
                    2147483646 + BIP32_HARDEN,
                    2,
                ],
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_3() {
        let seed = hex::decode(&"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();

        let xpriv = DerivedXPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();

        let descendants = [KeyDeriv {
            path: &[0 + BIP32_HARDEN],
        }];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn it_can_sign_and_verify() {
        let digest = [1u8; 32];
        let wrong_digest = [2u8; 32];
        let backend = Secp256k1::static_ref();

        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(backend)).unwrap();
        let fake_deriv = KeyDerivation {
            root: [0, 0, 0, 0].into(),
            path: (0..0).collect(),
        };

        let mut key = DerivedXPriv::new(xpriv, fake_deriv);
        let mut key_pub = DerivedXPub::from_signing_key(&key).unwrap();
        // These had to go somewhere. here is as good as any
        key.set_backend(backend);
        key_pub.set_backend(backend);

        // sign_digest + verify_digest
        let sig = key.sign_digest(digest).unwrap();
        key_pub.verify_digest(digest, &sig).unwrap();

        let err_bad_sig = key_pub.verify_digest(wrong_digest, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_digest_recoverable + verify_digest_recoverable
        let sig = key.sign_digest_recoverable(digest).unwrap();
        key_pub.verify_digest_recoverable(digest, &sig).unwrap();

        let err_bad_sig = key_pub.verify_digest_recoverable(wrong_digest, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_with_hash + verify_with_hash
        let hash_func = |digest: &[u8]| {
            let mut buf = [0u8; 32];
            buf[..5].copy_from_slice(&digest[..5]);
            buf
        };
        let sig = key.sign_with_hash(&digest[..], &hash_func).unwrap();
        key_pub
            .verify_with_hash(&digest[..], &hash_func, &sig)
            .unwrap();

        let err_bad_sig = key_pub.verify_with_hash(&wrong_digest[..], &hash_func, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_recoverable_with_hash + verify_recoverable_with_hash
        let hash_func = |digest: &[u8]| {
            let mut buf = [0u8; 32];
            buf[..5].copy_from_slice(&digest[..5]);
            buf
        };
        let sig = key
            .sign_recoverable_with_hash(&digest[..], &hash_func)
            .unwrap();
        key_pub
            .verify_recoverable_with_hash(&digest[..], &hash_func, &sig)
            .unwrap();

        let err_bad_sig = key_pub.verify_recoverable_with_hash(&wrong_digest[..], &hash_func, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign + verify
        let sig = key.sign(&digest[..]).unwrap();
        key_pub.verify(&digest[..], &sig).unwrap();

        let err_bad_sig = key_pub.verify(&wrong_digest[..], &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_recoverable + verify_recoverable
        let sig = key.sign_recoverable(&digest[..]).unwrap();
        key_pub.verify_recoverable(&digest[..], &sig).unwrap();

        let err_bad_sig = key_pub.verify_recoverable(&wrong_digest[..], &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }
    }

    #[test]
    fn it_can_descendant_sign_and_verify() {
        let digest = [1u8; 32];
        let wrong_digest = [2u8; 32];
        let backend = Secp256k1::static_ref();

        let path = vec![0u32, 1, 2];

        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(backend)).unwrap();
        let fake_deriv = KeyDerivation {
            root: [0, 0, 0, 0].into(),
            path: (0..0).collect(),
        };

        let mut key = DerivedXPriv::new(xpriv, fake_deriv.clone());
        let mut key_pub = DerivedXPub::from_signing_key(&key).unwrap();
        // These had to go somewhere. here is as good as any
        assert_eq!(key.derivation(), &fake_deriv);
        key.set_backend(backend);
        key_pub.set_backend(backend);

        // sign_digest + verify_digest
        let sig = key.descendant_sign_digest(&path, digest).unwrap();
        key_pub
            .descendant_verify_digest(&path, digest, &sig)
            .unwrap();

        let err_bad_sig = key_pub.descendant_verify_digest(&path, wrong_digest, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_digest_recoverable + verify_digest_recoverable
        let sig = key
            .descendant_sign_digest_recoverable(&path, digest)
            .unwrap();
        key_pub
            .descendant_verify_digest_recoverable(&path, digest, &sig)
            .unwrap();

        let err_bad_sig = key_pub.descendant_verify_digest_recoverable(&path, wrong_digest, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_with_hash + verify_with_hash
        let hash_func = |digest: &[u8]| {
            let mut buf = [0u8; 32];
            buf[..5].copy_from_slice(&digest[..5]);
            buf
        };
        let sig = key
            .descendant_sign_with_hash(&path, &digest[..], &hash_func)
            .unwrap();
        key_pub
            .descendant_verify_with_hash(&path, &digest[..], &hash_func, &sig)
            .unwrap();

        let err_bad_sig =
            key_pub.descendant_verify_with_hash(&path, &wrong_digest[..], &hash_func, &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_recoverable_with_hash + verify_recoverable_with_hash
        let hash_func = |digest: &[u8]| {
            let mut buf = [0u8; 32];
            buf[..5].copy_from_slice(&digest[..5]);
            buf
        };
        let sig = key
            .descendant_sign_recoverable_with_hash(&path, &digest[..], &hash_func)
            .unwrap();
        key_pub
            .descendant_verify_recoverable_with_hash(&path, &digest[..], &hash_func, &sig)
            .unwrap();

        let err_bad_sig = key_pub.descendant_verify_recoverable_with_hash(
            &path,
            &wrong_digest[..],
            &hash_func,
            &sig,
        );
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign + verify
        let sig = key.descendant_sign(&path, &digest[..]).unwrap();
        key_pub.descendant_verify(&path, &digest[..], &sig).unwrap();

        let err_bad_sig = key_pub.descendant_verify(&path, &wrong_digest[..], &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // sign_recoverable + verify_recoverable
        let sig = key.descendant_sign_recoverable(&path, &digest[..]).unwrap();
        key_pub
            .descendant_verify_recoverable(&path, &digest[..], &sig)
            .unwrap();

        let err_bad_sig = key_pub.descendant_verify_recoverable(&path, &wrong_digest[..], &sig);
        match err_bad_sig {
            Err(Bip32Error::BackendError(_)) => {}
            _ => assert!(false, "expected signature validation error"),
        }

        // Sig serialize/deserialize
        let der_sig = hex::decode("3045022100e838d64bb95cdacc1b93f94ad8c2fcc10441e672f66565aca374d5a955d99672022022283ac21bc8c64b7265e71b1972b051b1a818a99ae0db3d563489e55b9826a3").unwrap();
        let vrs = (
            1,
            [
                232, 56, 214, 75, 185, 92, 218, 204, 27, 147, 249, 74, 216, 194, 252, 193, 4, 65,
                230, 114, 246, 101, 101, 172, 163, 116, 213, 169, 85, 217, 150, 114,
            ],
            [
                34, 40, 58, 194, 27, 200, 198, 75, 114, 101, 231, 27, 25, 114, 176, 81, 177, 168,
                24, 169, 154, 224, 219, 61, 86, 52, 137, 229, 91, 152, 38, 163,
            ],
        );
        assert_eq!(sig.to_der(), der_sig);
        assert_eq!(sig.serialize_vrs(), vrs);
        assert_eq!(
            sig.without_recovery(),
            backend::Signature::try_from_der(&der_sig).unwrap()
        );
        assert_eq!(
            sig,
            backend::RecoverableSignature::deserialize_vrs(vrs).unwrap()
        );

        let err_no_rec_id = backend::RecoverableSignature::try_from_der(&der_sig);
        match err_no_rec_id {
            Err(Bip32Error::NoRecoveryID) => {}
            _ => assert!(false, "expected err no rec id"),
        };
    }

    #[test]
    fn it_derives_verifying_keys() {
        let backend = Secp256k1::static_ref();
        let fake_deriv = KeyDerivation {
            root: [0, 0, 0, 0].into(),
            path: (0..0).collect(),
        };

        let key = crate::curve::Privkey::from_privkey_array([1u8; 32]).unwrap();

        let privkey = crate::keys::Privkey {
            key,
            backend: Some(backend),
        };

        let key = DerivedPrivkey::new(privkey, fake_deriv);

        key.derive_verifying_key().unwrap();
    }

    #[test]
    fn it_instantiates_derived_xprivs_from_seeds() {
        let backend = Secp256k1::static_ref();
        GenericDerivedXPriv::custom_root_from_seed(&[0u8; 32][..], None, backend).unwrap();

        let err_too_short =
            GenericDerivedXPriv::custom_root_from_seed(&[0u8; 2][..], None, backend);
        match err_too_short {
            Err(Bip32Error::SeedTooShort) => {}
            _ => assert!(false, "expected err too short"),
        }

        let err_too_short =
            GenericDerivedXPriv::custom_root_from_seed(&[0u8; 2][..], None, backend);
        match err_too_short {
            Err(Bip32Error::SeedTooShort) => {}
            _ => assert!(false, "expected err too short"),
        }
    }

    #[test]
    fn it_checks_ancestry() {
        let backend = Secp256k1::static_ref();
        let m = GenericDerivedXPriv::custom_root_from_seed(&[0u8; 32][..], None, backend).unwrap();
        let m2 = GenericDerivedXPriv::custom_root_from_seed(&[1u8; 32][..], None, backend).unwrap();
        let m_pub = GenericDerivedXPub::from_signing_key(&m).unwrap();
        let cases = [
            (&m, &m_pub, true),
            (&m2, &m_pub, false),
            (&m, &m2.derive_verifying_key().unwrap(), false),
            (
                &m,
                &m.derive_private_child(33)
                    .unwrap()
                    .derive_verifying_key()
                    .unwrap(),
                true,
            ),
            (&m, &m_pub.derive_public_child(33).unwrap(), true),
            (
                &m,
                &m2.derive_private_child(33)
                    .unwrap()
                    .derive_verifying_key()
                    .unwrap(),
                false,
            ),
        ];
        for case in cases.iter() {
            assert_eq!(case.0.is_private_ancestor_of(case.1).unwrap(), case.2);
        }
    }
}
