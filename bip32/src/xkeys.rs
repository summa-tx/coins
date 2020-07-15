use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{
    curve::model::{ScalarDeserialize, Secp256k1Backend},
    keys::{GenericPrivkey, GenericPubkey},
    model::*,
    primitives::{ChainCode, Hint, KeyFingerprint, XKeyInfo},
    Bip32Error, BIP32_HARDEN, CURVE_ORDER,
};

type HmacSha512 = Hmac<Sha512>;

/// A BIP32 Extended privkey using the library's compiled-in secp256k1 backend. This defaults to
/// libsecp for native, and parity's rust secp for wasm targets
///
/// For interface documentation see the page for
/// [GenericXPriv](struct.GenericXPriv.html).
pub type XPriv = GenericXPriv<'static, crate::curve::Secp256k1<'static>>;

impl XPriv {
    /// Generate a customized master node using the static backend
    pub fn master_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<XPriv, Bip32Error> {
        Self::custom_master_node(hmac_key, data, hint, crate::curve::Secp256k1::static_ref())
    }

    /// Generate a master node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn root_from_seed(data: &[u8], hint: Option<Hint>) -> Result<XPriv, Bip32Error> {
        Self::custom_root_from_seed(data, hint, crate::curve::Secp256k1::static_ref())
    }
}

/// A BIP32 Extended pubkey using the library's compiled-in secp256k1 backend. This defaults to
/// libsecp for native, and parity's rust secp for wasm targets
///
/// For interface documentation see the page for
/// [GenericXPub](struct.GenericXPub.html).
pub type XPub = GenericXPub<'static, crate::curve::Secp256k1<'static>>;

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

/// A BIP32 Extended privkey. This key is genericized to accept any compatibile backend.
#[derive(Clone, Debug, PartialEq)]
pub struct GenericXPriv<'a, T: Secp256k1Backend> {
    /// The extended key information
    pub info: XKeyInfo,
    /// The associated secp256k1 key
    pub privkey: GenericPrivkey<'a, T>,
}

inherit_has_privkey!(GenericXPriv.privkey);
inherit_backend!(GenericXPriv.privkey);

impl<'a, T: Secp256k1Backend> GenericXPriv<'a, T> {
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
            // This can only be tested by mocking hmac_and_split
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
    pub fn custom_root_from_seed(
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

impl<'a, T: Secp256k1Backend> HasXKeyInfo for GenericXPriv<'a, T> {
    fn xkey_info(&self) -> &XKeyInfo {
        &self.info
    }
}

impl<'a, T: Secp256k1Backend> SigningKey<'a, T> for GenericXPriv<'a, T> {
    /// The corresponding verifying key
    type VerifyingKey = GenericXPub<'a, T>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        self.to_xpub()
    }
}

impl<'a, T: Secp256k1Backend> DerivePrivateChild<'a, T> for GenericXPriv<'a, T> {
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
pub struct GenericXPub<'a, T: Secp256k1Backend> {
    /// The extended key information
    pub info: XKeyInfo,
    /// The associated secp256k1 key
    pub pubkey: GenericPubkey<'a, T>,
}

inherit_has_pubkey!(GenericXPub.pubkey);
inherit_backend!(GenericXPub.pubkey);

impl<'a, T: Secp256k1Backend> GenericXPub<'a, T> {
    /// Derive an XPub from an xpriv
    pub fn from_xpriv(xpriv: &GenericXPriv<'a, T>) -> Result<GenericXPub<'a, T>, Bip32Error> {
        xpriv.to_xpub()
    }
}

impl<'a, T: Secp256k1Backend> HasXKeyInfo for GenericXPub<'a, T> {
    fn xkey_info(&self) -> &XKeyInfo {
        &self.info
    }
}

impl<'a, T: Secp256k1Backend> VerifyingKey<'a, T> for GenericXPub<'a, T> {
    type SigningKey = GenericXPriv<'a, T>;
}

impl<'a, T: Secp256k1Backend> DerivePublicChild<'a, T> for GenericXPub<'a, T> {
    fn derive_public_child(&self, index: u32) -> Result<GenericXPub<'a, T>, Bip32Error> {
        if index >= BIP32_HARDEN {
            return Err(Bip32Error::HardenedDerivationFailed);
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        curve::Secp256k1,
        enc::{MainnetEncoder, XKeyEncoder},
        keys::Pubkey,
        primitives::*,
    };

    use hex;

    struct KeyDeriv<'a> {
        pub path: &'a [u32],
        pub xpub: String,
        pub xpriv: String,
    }

    fn validate_descendant<'a>(d: &KeyDeriv, m: &XPriv) {
        let xpriv = m.derive_private_path(d.path).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&d.xpriv, xpriv.backend().ok()).unwrap();
        let deser_xpub = MainnetEncoder::xpub_from_base58(&d.xpub, xpriv.backend().ok()).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(), d.xpriv);
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(MainnetEncoder::xpub_to_base58(&xpub).unwrap(), d.xpub);
    }

    #[test]
    fn bip32_vector_1() {
        let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let backend = Secp256k1::static_ref();

        let xpriv = XPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let expected_xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let expected_xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        let deser_xpub = MainnetEncoder::xpub_from_base58(&expected_xpub, Some(backend)).unwrap();
        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(backend)).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(
            MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(),
            expected_xpriv
        );
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(
            MainnetEncoder::xpub_to_base58(&xpub).unwrap(),
            expected_xpub
        );

        let descendants = [
            KeyDeriv {
                path: &[0 + BIP32_HARDEN],
                xpub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw".to_owned(),
                xpriv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1],
                xpub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ".to_owned(),
                xpriv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN],
                xpub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5".to_owned(),
                xpriv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2],
                xpub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV".to_owned(),
                xpriv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334".to_owned(),
            },
            KeyDeriv {
                path: &[0 + BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2, 1000000000],
                xpub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy".to_owned(),
                xpriv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_2() {
        let seed = hex::decode(&"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let backend = Secp256k1::static_ref();

        let xpriv = XPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let expected_xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        let expected_xpriv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";

        let deser_xpub = MainnetEncoder::xpub_from_base58(&expected_xpub, Some(backend)).unwrap();
        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(backend)).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(
            MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(),
            expected_xpriv
        );
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(
            MainnetEncoder::xpub_to_base58(&xpub).unwrap(),
            expected_xpub
        );

        let descendants = [
            KeyDeriv {
                path: &[0],
                xpub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH".to_owned(),
                xpriv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN],
                xpub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a".to_owned(),
                xpriv: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1],
                xpub: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon".to_owned(),
                xpriv: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1, 2147483646 + BIP32_HARDEN],
                xpub: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL".to_owned(),
                xpriv: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc".to_owned(),
            },
            KeyDeriv {
                path: &[0, 2147483647 + BIP32_HARDEN, 1, 2147483646 + BIP32_HARDEN, 2],
                xpub: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt".to_owned(),
                xpriv: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_3() {
        let seed = hex::decode(&"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
        let backend = Secp256k1::static_ref();

        let xpriv = XPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();
        let xpub = xpriv.to_xpub().unwrap();

        let expected_xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
        let expected_xpriv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";

        let deser_xpub = MainnetEncoder::xpub_from_base58(&expected_xpub, Some(backend)).unwrap();
        let deser_xpriv =
            MainnetEncoder::xpriv_from_base58(&expected_xpriv, Some(backend)).unwrap();

        assert_eq!(&xpriv, &deser_xpriv);
        assert_eq!(
            MainnetEncoder::xpriv_to_base58(&xpriv).unwrap(),
            expected_xpriv
        );
        assert_eq!(&xpub, &deser_xpub);
        assert_eq!(
            MainnetEncoder::xpub_to_base58(&xpub).unwrap(),
            expected_xpub
        );

        let descendants = [
            KeyDeriv {
                path: &[0 + BIP32_HARDEN],
                xpub: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y".to_owned(),
                xpriv: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(&case, &xpriv);
        }
    }

    #[test]
    fn it_can_sign_and_verify() {
        let digest = [1u8; 32];
        let backend = Secp256k1::static_ref();
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(backend)).unwrap();

        let child = xpriv.derive_private_child(33).unwrap();
        let sig = child.sign_digest(digest).unwrap();

        let child_xpub = child.to_xpub().unwrap();
        child_xpub.verify_digest(digest, &sig).unwrap();
    }

    #[test]
    fn it_can_verify_and_recover_from_signatures() {
        let digest = [1u8; 32];
        let backend = Secp256k1::static_ref();
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, Some(backend)).unwrap();

        let child = xpriv.derive_private_child(33).unwrap();

        let sig = child.sign_digest_recoverable(digest).unwrap();

        let child_xpub = child.to_xpub().unwrap();
        child_xpub.verify_digest_recoverable(digest, &sig).unwrap();

        let recovered =
            Pubkey::recover_from_signed_digest(xpriv.backend().unwrap(), digest, &sig).unwrap();
        assert_eq!(&recovered.pubkey(), &child_xpub.pubkey());
    }

    #[test]
    fn it_can_read_keys_without_a_backend() {
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let _xpriv: XPriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, None).unwrap();
    }


    #[test]
    fn print_key() {
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv: XPriv = MainnetEncoder::xpriv_from_base58(&xpriv_str, None).unwrap();
        println!("{:?}", xpriv);
    }
}
