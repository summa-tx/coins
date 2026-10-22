use coins_core::hashes::{Hash160, Hash160Digest, MarkedDigest, MarkedDigestOutput};
use hmac::{Hmac, KeyInit, Mac};
use k256::{ecdsa, elliptic_curve::sec1::FromSec1Point};
use sha2::Sha512;
use std::{
    convert::{TryFrom, TryInto},
    ops::{AddAssign, Mul},
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    BIP32_HARDEN, Bip32Error,
    enc::{MAINNET, NetworkVersions},
    path::DerivationPath,
    primitives::{ChainCode, Hint, KeyFingerprint, XKeyInfo},
};

/// The BIP32-defined seed used for derivation of the root node.
pub const SEED: &[u8; 12] = b"Bitcoin seed";

fn hmac_and_split(
    seed: &[u8],
    data: &[u8],
) -> Result<(Zeroizing<k256::NonZeroScalar>, ChainCode), Bip32Error> {
    let mut mac = Hmac::<Sha512>::new_from_slice(seed).expect("key length is ok");
    mac.update(data);
    let result = Zeroizing::new(mac.finalize().into_bytes());

    let left = Zeroizing::new(k256::NonZeroScalar::try_from(&result[..32])?);

    let mut chain_code = ChainCode([0u8; 32]);
    chain_code.0.copy_from_slice(&result[32..]);

    Ok((left, chain_code))
}

/// A Parent key can be used to derive children.
pub trait Parent: Sized + Clone {
    /// Derive the child at `index`. Note that this may produce the child at
    /// `index+1` in rare circumstances. For public keys this will derive public
    /// children. For private keys it will derive private children.
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error>;

    /// Derive a series of child indices. Allows traversing several levels of the tree at once.
    /// Accepts an iterator producing u32, or a string.
    fn derive_path<E, P>(&self, p: P) -> Result<Self, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        let path: DerivationPath = p.try_into().map_err(Into::into)?;

        if path.is_empty() {
            return Ok(self.clone());
        }

        let mut current = self.to_owned();
        for index in path.iter() {
            current = current.derive_child(*index)?;
        }
        Ok(current)
    }
}

/// A BIP32 eXtended Privkey
///
/// The signing key and chain code are zeroized on drop, and comparisons are constant time.
pub struct XPriv {
    pub(crate) key: ecdsa::SigningKey,
    pub(crate) xkey_info: XKeyInfo,
}

impl Drop for XPriv {
    fn drop(&mut self) {
        // The signing key zeroizes itself. The chain code is not secret on its own, but together
        // with the xpub and any non-hardened child private key it reveals this private key.
        self.xkey_info.chain_code.zeroize();
    }
}

impl ZeroizeOnDrop for XPriv {}

impl ConstantTimeEq for XPriv {
    fn ct_eq(&self, other: &Self) -> Choice {
        let public = self.xkey_info.depth == other.xkey_info.depth
            && self.xkey_info.parent == other.xkey_info.parent
            && self.xkey_info.index == other.xkey_info.index;
        self.key.ct_eq(&other.key)
            & self.xkey_info.chain_code.ct_eq(&other.xkey_info.chain_code)
            & Choice::from(public as u8)
    }
}

impl PartialEq for XPriv {
    fn eq(&self, other: &XPriv) -> bool {
        self.ct_eq(other).into()
    }
}

impl Clone for XPriv {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            xkey_info: self.xkey_info,
        }
    }
}

inherit_signer!(XPriv.key);

impl std::fmt::Debug for XPriv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XPriv")
            .field("key fingerprint", &self.fingerprint())
            .field("depth", &self.xkey_info.depth)
            .field("parent", &self.xkey_info.parent)
            .field("index", &self.xkey_info.index)
            .field("hint", &self.xkey_info.hint)
            .field("network", self.xkey_info.network)
            .finish_non_exhaustive()
    }
}

impl AsRef<XPriv> for XPriv {
    fn as_ref(&self) -> &XPriv {
        self
    }
}

impl AsRef<XKeyInfo> for XPriv {
    fn as_ref(&self) -> &XKeyInfo {
        &self.xkey_info
    }
}

impl AsRef<ecdsa::SigningKey> for XPriv {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.key
    }
}

impl XPriv {
    /// Instantiate a new XPriv.
    pub const fn new(key: ecdsa::SigningKey, xkey_info: XKeyInfo) -> Self {
        Self { key, xkey_info }
    }

    /// Set the network whose version bytes this key serializes with. Root constructors default
    /// to mainnet.
    pub const fn set_network(&mut self, network: &'static NetworkVersions) {
        self.xkey_info.network = network;
    }

    /// Derive the associated XPub
    pub fn verify_key(&self) -> XPub {
        XPub {
            key: self.key.verifying_key().to_owned(),
            xkey_info: self.xkey_info,
        }
    }

    /// The fingerprint is the first 4 bytes of the HASH160 of the public key
    pub fn fingerprint(&self) -> KeyFingerprint {
        self.verify_key().fingerprint()
    }

    /// Generate a customized root node
    pub fn root_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<XPriv, Bip32Error> {
        Self::custom_root_node(hmac_key, data, hint)
    }

    /// Generate a root node from some seed data. Uses the BIP32-standard hmac
    /// key.
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn root_from_seed(data: &[u8], hint: Option<Hint>) -> Result<XPriv, Bip32Error> {
        Self::custom_root_from_seed(data, hint)
    }

    /// Instantiate a root node using a custom HMAC key.
    pub fn custom_root_node(
        hmac_key: &[u8],
        data: &[u8],
        hint: Option<Hint>,
    ) -> Result<XPriv, Bip32Error> {
        if data.len() < 16 {
            return Err(Bip32Error::SeedTooShort);
        }
        let parent = KeyFingerprint([0u8; 4]);
        let (key, chain_code) = hmac_and_split(hmac_key, data)?;
        if bool::from(key.is_zero()) {
            // This can only be tested by mocking hmac_and_split
            return Err(Bip32Error::InvalidKey);
        }

        let key = ecdsa::SigningKey::from(*key);

        Ok(XPriv {
            key,
            xkey_info: XKeyInfo {
                depth: 0,
                parent,
                index: 0,
                chain_code,
                hint: hint.unwrap_or(Hint::SegWit),
                network: &MAINNET,
            },
        })
    }

    /// Generate a root node from some seed data. Uses the BIP32-standard hmac key.
    ///
    ///
    /// # Important:
    ///
    /// Use a seed of AT LEAST 128 bits.
    pub fn custom_root_from_seed(data: &[u8], hint: Option<Hint>) -> Result<XPriv, Bip32Error> {
        Self::custom_root_node(SEED, data, hint)
    }

    /// Derive a series of child indices. Allows traversing several levels of the tree at once.
    /// Accepts an iterator producing u32, or a string.
    pub fn derive_path<E, P>(&self, p: P) -> Result<Self, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        let path: DerivationPath = p.try_into().map_err(Into::into)?;

        if path.is_empty() {
            return Ok(self.clone());
        }

        let mut current = self.to_owned();
        for index in path.iter() {
            current = current.derive_child(*index)?;
        }
        Ok(current)
    }
}

impl Parent for XPriv {
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        let hardened = index >= BIP32_HARDEN;

        let key: &ecdsa::SigningKey = self.as_ref();

        // `0x00 || privkey || index` for hardened children, `pubkey || index` otherwise.
        let mut data = Zeroizing::new([0u8; 37]);
        if hardened {
            data[1..33].copy_from_slice(&Zeroizing::new(key.to_bytes()));
        } else {
            data[..33].copy_from_slice(&key.verifying_key().to_sec1_bytes());
        };
        data[33..].copy_from_slice(&index.to_be_bytes());

        let res = hmac_and_split(&self.xkey_info.chain_code.0, &*data);
        let (tweak, chain_code) = match res {
            Ok((tweak, chain_code)) => (tweak, chain_code),
            _ => return self.derive_child(index + 1),
        };

        let tweaked = Zeroizing::new(tweak.add(key.as_nonzero_scalar()));

        let tweaked: Zeroizing<k256::NonZeroScalar> = Zeroizing::new(
            Option::from(k256::NonZeroScalar::new(*tweaked)).ok_or(Bip32Error::BadTweak)?,
        );

        Ok(Self {
            key: ecdsa::SigningKey::from(*tweaked),
            xkey_info: XKeyInfo {
                depth: self.xkey_info.depth + 1,
                parent: self.fingerprint(),
                index,
                chain_code,
                hint: self.xkey_info.hint,
                network: self.xkey_info.network,
            },
        })
    }
}

#[derive(Copy)]
/// A BIP32 eXtended Public key
pub struct XPub {
    pub(crate) key: ecdsa::VerifyingKey,
    pub(crate) xkey_info: XKeyInfo,
}

inherit_verifier!(XPub.key);

impl Clone for XPub {
    fn clone(&self) -> Self {
        *self
    }
}

impl std::fmt::Debug for XPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XPub")
            .field("public key", &self.key.to_sec1_bytes())
            .field("key fingerprint", &self.fingerprint())
            .field("key info", &self.xkey_info)
            .finish()
    }
}

impl AsRef<XPub> for XPub {
    fn as_ref(&self) -> &XPub {
        self
    }
}

impl AsRef<XKeyInfo> for XPub {
    fn as_ref(&self) -> &XKeyInfo {
        &self.xkey_info
    }
}

impl AsRef<ecdsa::VerifyingKey> for XPub {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.key
    }
}

impl XPub {
    /// Instantiate a new XPub
    pub const fn new(key: ecdsa::VerifyingKey, xkey_info: XKeyInfo) -> Self {
        Self { key, xkey_info }
    }

    /// Set the network whose version bytes this key serializes with. Root constructors default
    /// to mainnet.
    pub const fn set_network(&mut self, network: &'static NetworkVersions) {
        self.xkey_info.network = network;
    }

    /// The fingerprint is the first 4 bytes of the HASH160 of the serialized
    /// public key.
    pub fn fingerprint(&self) -> KeyFingerprint {
        let digest = self.pubkey_hash160();
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&digest.as_slice()[..4]);
        buf.into()
    }

    /// Return the bitcoin HASH160 of the serialized public key
    pub fn pubkey_hash160(&self) -> Hash160Digest {
        Hash160::digest_marked(self.key.to_sec1_bytes().as_ref())
    }

    /// Construct a BIP-328 "synthetic xpub" root from a MuSig2 plain aggregate public key.
    ///
    /// Per BIP-328, this fixes the depth, parent fingerprint, and child number to 0, and
    /// attaches the fixed chain code [`ChainCode::MUSIG2_SYNTHETIC_ROOT`]. As there is no
    /// aggregate private key, only unhardened derivation from the result is possible.
    ///
    /// See <https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki>.
    ///
    /// Signing for derived children requires the `I_L` tweak from each derivation step, which
    /// [`Parent::derive_child`] does not expose. Open an issue if you need access to the tweaks.
    pub const fn musig2_synthetic_root(key: ecdsa::VerifyingKey) -> Self {
        Self {
            key,
            xkey_info: XKeyInfo {
                depth: 0,
                parent: KeyFingerprint([0u8; 4]),
                index: 0,
                chain_code: ChainCode::MUSIG2_SYNTHETIC_ROOT,
                hint: Hint::Legacy,
                network: &MAINNET,
            },
        }
    }

    /// Returns `true` if this xpub's depth, parent fingerprint, child number, and chain code
    /// match the BIP-328 synthetic xpub root shape for a MuSig2 aggregate key.
    ///
    /// See <https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki>.
    pub fn is_musig2_synthetic_root(&self) -> bool {
        self.xkey_info.depth == 0
            && self.xkey_info.parent == KeyFingerprint([0u8; 4])
            && self.xkey_info.index == 0
            && self.xkey_info.chain_code == ChainCode::MUSIG2_SYNTHETIC_ROOT
    }
}

impl PartialEq for XPub {
    fn eq(&self, other: &XPub) -> bool {
        self.key == other.key
    }
}

impl Parent for XPub {
    fn derive_child(&self, index: u32) -> Result<XPub, Bip32Error> {
        if index >= BIP32_HARDEN {
            return Err(Bip32Error::HardenedDerivationFailed);
        }
        let mut data = vec![];
        // secp256k1 points are converted to compressed form
        // https://github.com/RustCrypto/elliptic-curves/blob/3ee0ba1aa5bb74777928c21bb198d2a696f0dd9d/k256/src/lib.rs#L98
        data.extend(self.key.to_sec1_bytes().iter());
        data.extend(index.to_be_bytes());

        let res = hmac_and_split(&self.xkey_info.chain_code.0, &data);

        let (tweak, chain_code) = match res {
            Ok((tweak, chain_code)) => (tweak, chain_code),
            _ => return self.derive_child(index + 1),
        };

        if bool::from(tweak.is_zero()) {
            return self.derive_child(index + 1);
        }

        let parent_key =
            k256::ProjectivePoint::from_sec1_point(&self.key.to_sec1_point(true)).unwrap();
        let mut tweak_point = k256::ProjectivePoint::GENERATOR.mul(**tweak);
        tweak_point.add_assign(parent_key);

        let key = ecdsa::VerifyingKey::from_affine(tweak_point.to_affine())?;
        Ok(Self {
            key,
            xkey_info: XKeyInfo {
                depth: self.xkey_info.depth + 1,
                parent: self.fingerprint(),
                index,
                chain_code,
                hint: self.xkey_info.hint,
                network: self.xkey_info.network,
            },
        })
    }
}

impl std::str::FromStr for XPriv {
    type Err = Bip32Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        XPriv::from_base58(s)
    }
}

impl std::str::FromStr for XPub {
    type Err = Bip32Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        XPub::from_base58(s)
    }
}

impl serde::Serialize for XPub {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base58())
    }
}

impl<'de> serde::Deserialize<'de> for XPub {
    fn deserialize<D>(deserializer: D) -> Result<XPub, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(crate::enc::XPubVisitor(None))
    }
}

impl serde::Serialize for XPriv {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base58())
    }
}

impl<'de> serde::Deserialize<'de> for XPriv {
    fn deserialize<D>(deserializer: D) -> Result<XPriv, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(crate::enc::XPrivVisitor(None))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::primitives::*;
    use coins_core::hashes::Hash256;
    use k256::ecdsa::signature::{DigestSigner, DigestVerifier};

    use hex;

    struct KeyDeriv<'a> {
        pub(crate) path: &'a [u32],
        pub(crate) xpub: String,
        pub(crate) xpriv: String,
    }

    fn validate_descendant(d: &KeyDeriv, m: &XPriv) {
        let xpriv = m.derive_path(d.path).unwrap();
        let xpub = xpriv.verify_key();

        // let m_pub = m.verify_key();
        // let xpub_2 = m_pub.derive_path(d.path).unwrap();
        // assert_eq!(&xpub, &xpub_2);

        let deser_xpriv = XPriv::from_base58(&d.xpriv).unwrap();
        let deser_xpub = XPub::from_base58(&d.xpub).unwrap();

        assert_eq!(&xpriv.key.to_bytes(), &deser_xpriv.key.to_bytes());
        assert_eq!(xpriv.to_base58().as_str(), d.xpriv);
        assert_eq!(&xpub.key.to_sec1_bytes(), &deser_xpub.key.to_sec1_bytes());
        assert_eq!(xpub.to_base58(), d.xpub);
    }

    #[test]
    fn xpriv_debug_redacts_secrets() {
        let xpriv = XPriv::root_from_seed(&[0xab; 32], None).unwrap();
        let debug = format!("{xpriv:?}");
        let key_hex = hex::encode(xpriv.key.to_bytes());
        let chain_code_dec = format!("{:?}", xpriv.xkey_info.chain_code.0);
        assert!(!debug.contains(&key_hex));
        assert!(!debug.contains(&chain_code_dec));
        assert!(!debug.contains("chain_code"));
    }

    #[test]
    fn xpriv_eq_compares_key_and_chain_code() {
        let a = XPriv::root_from_seed(&[1; 32], None).unwrap();
        let b = XPriv::root_from_seed(&[2; 32], None).unwrap();
        assert_eq!(a, a.clone());
        assert_ne!(a, b);

        let mut c = a.clone();
        c.xkey_info.chain_code.0[0] ^= 1;
        assert_ne!(a, c);
    }

    #[test]
    fn bip32_vector_1() {
        let seed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let xpriv = XPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();
        let xpub = xpriv.verify_key();

        let expected_xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let expected_xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        let deser_xpub = XPub::from_base58(expected_xpub).unwrap();
        let deser_xpriv = XPriv::from_base58(expected_xpriv).unwrap();

        assert_eq!(&xpriv.key.to_bytes(), &deser_xpriv.key.to_bytes());
        assert_eq!(xpriv.to_base58().as_str(), expected_xpriv);
        assert_eq!(&xpub.key.to_sec1_bytes(), &deser_xpub.key.to_sec1_bytes());
        assert_eq!(xpub.to_base58(), expected_xpub);

        let descendants = [
            KeyDeriv {
                path: &[BIP32_HARDEN],
                xpub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw".to_owned(),
                xpriv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7".to_owned(),
            },
            KeyDeriv {
                path: &[BIP32_HARDEN, 1],
                xpub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ".to_owned(),
                xpriv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs".to_owned(),
            },
            KeyDeriv {
                path: &[BIP32_HARDEN, 1, 2 + BIP32_HARDEN],
                xpub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5".to_owned(),
                xpriv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM".to_owned(),
            },
            KeyDeriv {
                path: &[BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2],
                xpub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV".to_owned(),
                xpriv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334".to_owned(),
            },
            KeyDeriv {
                path: &[BIP32_HARDEN, 1, 2 + BIP32_HARDEN, 2, 1000000000],
                xpub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy".to_owned(),
                xpriv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_2() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();

        let xpriv = XPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();
        let xpub = xpriv.verify_key();

        let expected_xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        let expected_xpriv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";

        let deser_xpub = XPub::from_base58(expected_xpub).unwrap();
        let deser_xpriv = XPriv::from_base58(expected_xpriv).unwrap();

        assert_eq!(&xpriv.key.to_bytes(), &deser_xpriv.key.to_bytes());
        assert_eq!(xpriv.to_base58().as_str(), expected_xpriv);
        assert_eq!(&xpub.key.to_sec1_bytes(), &deser_xpub.key.to_sec1_bytes());
        assert_eq!(xpub.to_base58(), expected_xpub);

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
            validate_descendant(case, &xpriv);
        }
    }

    #[test]
    fn bip32_vector_3() {
        let seed = hex::decode("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();

        let xpriv = XPriv::root_from_seed(&seed, Some(Hint::Legacy)).unwrap();
        let xpub = xpriv.verify_key();

        let expected_xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
        let expected_xpriv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";

        let deser_xpub = XPub::from_base58(expected_xpub).unwrap();
        let deser_xpriv = XPriv::from_base58(expected_xpriv).unwrap();

        assert_eq!(&xpriv.key.to_bytes(), &deser_xpriv.key.to_bytes());
        assert_eq!(xpriv.to_base58().as_str(), expected_xpriv);
        assert_eq!(&xpub.key.to_sec1_bytes(), &deser_xpub.key.to_sec1_bytes());
        assert_eq!(xpub.to_base58(), expected_xpub);

        let descendants = [
            KeyDeriv {
                path: &[BIP32_HARDEN],
                xpub: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y".to_owned(),
                xpriv: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L".to_owned(),
            },
        ];

        for case in descendants.iter() {
            validate_descendant(case, &xpriv);
        }
    }

    #[test]
    fn it_can_sign_and_verify() {
        let digest = Hash256::default();
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv = XPriv::from_base58(&xpriv_str).unwrap();

        let child = xpriv.derive_child(33).unwrap();
        let sig: ecdsa::Signature = child.sign_digest(|d: &mut Hash256| *d = digest.clone());

        let child_xpub = child.verify_key();
        child_xpub
            .verify_digest(
                |d: &mut Hash256| {
                    *d = digest.clone();
                    Ok(())
                },
                &sig,
            )
            .unwrap();
    }

    #[test]
    fn it_can_verify_and_recover_from_signatures() {
        let digest = Hash256::default();

        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv = XPriv::from_base58(&xpriv_str).unwrap();

        let child = xpriv.derive_child(33).unwrap();

        let (sig, recovery_id): (ecdsa::Signature, ecdsa::RecoveryId) =
            child.sign_digest(|d: &mut Hash256| *d = digest.clone());

        let child_xpub = child.verify_key();
        child_xpub
            .verify_digest(
                |d: &mut Hash256| {
                    *d = digest.clone();
                    Ok(())
                },
                &sig,
            )
            .unwrap();

        let recovered =
            ecdsa::VerifyingKey::recover_from_digest(digest, &sig, recovery_id).unwrap();

        assert_eq!(&recovered.to_sec1_bytes(), &child_xpub.key.to_sec1_bytes());
    }

    #[test]
    fn it_can_read_keys() {
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let _xpriv: XPriv = XPriv::from_base58(&xpriv_str).unwrap();
    }

    #[test]
    fn print_key() {
        let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
        let xpriv: XPriv = XPriv::from_base58(&xpriv_str).unwrap();
        println!("{xpriv:?}");
    }

    // BIP-328 test vectors (aggregate pubkey, synthetic xpub):
    // https://github.com/bitcoin/bips/blob/master/bip-0328/vectors.json
    const BIP328_VECTORS: &[(&str, &str)] = &[
        (
            "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",
        ),
        (
            "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k",
        ),
        (
            "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ",
        ),
    ];

    fn bip328_aggregate_key(hex_pubkey: &str) -> ecdsa::VerifyingKey {
        ecdsa::VerifyingKey::from_sec1_bytes(&hex::decode(hex_pubkey).unwrap()).unwrap()
    }

    #[test]
    fn musig2_synthetic_root_matches_bip328_test_vectors() {
        for (agg_pubkey, expected_xpub) in BIP328_VECTORS {
            let synthetic = XPub::musig2_synthetic_root(bip328_aggregate_key(agg_pubkey));
            assert_eq!(synthetic.to_base58(), *expected_xpub);

            let parsed = XPub::from_base58(expected_xpub).unwrap();
            assert!(parsed.is_musig2_synthetic_root());
            assert_eq!(parsed.xkey_info, synthetic.xkey_info);
        }
    }

    #[test]
    fn it_identifies_musig2_synthetic_roots() {
        let synthetic = XPub::musig2_synthetic_root(bip328_aggregate_key(BIP328_VECTORS[0].0));
        assert!(synthetic.is_musig2_synthetic_root());

        let ordinary = XPub::from_base58(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .unwrap();
        assert!(!ordinary.is_musig2_synthetic_root());

        // Deriving a child moves depth away from 0, so it's no longer a synthetic root.
        let child = synthetic.derive_child(0).unwrap();
        assert!(!child.is_musig2_synthetic_root());
    }
}

#[cfg(test)]
#[path = "../ai-tests/xkeys.rs"]
mod ai_tests;
