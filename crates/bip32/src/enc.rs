use coins_core::hashes::{Digest, Hash256};
use k256::ecdsa;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Bip32Error,
    derived::{DerivedXPriv, DerivedXPub},
    path::KeyDerivation,
    primitives::{ChainCode, Hint, KeyFingerprint, XKeyInfo},
    xkeys::{XPriv, XPub},
};

/// Decode a bytevector from a base58 check string
///
/// The intermediate buffer and the result are zeroized, as the payload may be secret.
pub fn decode_b58_check(s: &str) -> Result<Zeroizing<Vec<u8>>, Bip32Error> {
    let mut data = Zeroizing::new(bs58::decode(s).into_vec()?);
    let (payload, checksum) = data
        .split_last_chunk::<4>()
        .ok_or(Bip32Error::BadB58Checksum)?;
    let len = payload.len();

    (Hash256::digest(payload)[..4] == checksum[..])
        .then(|| {
            data.truncate(len);
            data
        })
        .ok_or(Bip32Error::BadB58Checksum)
}

/// Encode a vec into a base58 check String
///
/// The intermediate buffer and the result are zeroized, as the payload may be secret.
pub fn encode_b58_check(v: &[u8]) -> Zeroizing<String> {
    let digest = &Hash256::digest(v);

    let mut data = Zeroizing::new(Vec::with_capacity(v.len() + 4));
    data.extend_from_slice(v);
    data.extend_from_slice(&digest[..4]);

    Zeroizing::new(bs58::encode(&*data).into_string())
}

/// A BIP-32 serialized extended private key: version (4), depth (1), parent fingerprint (4),
/// index (4), chain code (32), padding (1), and private key (32). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SerializedXPriv([u8; 78]);

/// A network's BIP-32/49/84 version prefixes, in big-endian u32 form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkVersions {
    /// BIP-32 private key version (`xprv` on mainnet).
    pub priv_legacy: u32,
    /// BIP-49 private key version (`yprv` on mainnet).
    pub priv_compatibility: u32,
    /// BIP-84 private key version (`zprv` on mainnet).
    pub priv_segwit: u32,
    /// BIP-32 public key version (`xpub` on mainnet).
    pub pub_legacy: u32,
    /// BIP-49 public key version (`ypub` on mainnet).
    pub pub_compatibility: u32,
    /// BIP-84 public key version (`zpub` on mainnet).
    pub pub_segwit: u32,
}

impl NetworkVersions {
    /// The private key version for the given hint.
    pub const fn priv_version(&self, hint: Hint) -> u32 {
        match hint {
            Hint::Legacy => self.priv_legacy,
            Hint::Compatibility => self.priv_compatibility,
            Hint::SegWit => self.priv_segwit,
        }
    }

    /// The public key version for the given hint.
    pub const fn pub_version(&self, hint: Hint) -> u32 {
        match hint {
            Hint::Legacy => self.pub_legacy,
            Hint::Compatibility => self.pub_compatibility,
            Hint::SegWit => self.pub_segwit,
        }
    }

    /// The hint for a private key version, if it belongs to this network.
    pub const fn priv_hint(&self, version: u32) -> Option<Hint> {
        if version == self.priv_legacy {
            Some(Hint::Legacy)
        } else if version == self.priv_compatibility {
            Some(Hint::Compatibility)
        } else if version == self.priv_segwit {
            Some(Hint::SegWit)
        } else {
            None
        }
    }

    /// The hint for a public key version, if it belongs to this network.
    pub const fn pub_hint(&self, version: u32) -> Option<Hint> {
        if version == self.pub_legacy {
            Some(Hint::Legacy)
        } else if version == self.pub_compatibility {
            Some(Hint::Compatibility)
        } else if version == self.pub_segwit {
            Some(Hint::SegWit)
        } else {
            None
        }
    }
}

/// Bitcoin mainnet version prefixes.
pub const MAINNET: NetworkVersions = NetworkVersions {
    priv_legacy: 0x0488_ADE4,
    priv_compatibility: 0x049d_7878,
    priv_segwit: 0x04b2_430c,
    pub_legacy: 0x0488_B21E,
    pub_compatibility: 0x049d_7cb2,
    pub_segwit: 0x04b2_4746,
};

/// Bitcoin testnet version prefixes.
pub const TESTNET: NetworkVersions = NetworkVersions {
    priv_legacy: 0x0435_8394,
    priv_compatibility: 0x044a_4e28,
    priv_segwit: 0x045f_18bc,
    pub_legacy: 0x0435_87CF,
    pub_compatibility: 0x044a_5262,
    pub_segwit: 0x045f_1cf6,
};

/// The networks a blind parse recognizes, tried in order.
const KNOWN: [&NetworkVersions; 2] = [&MAINNET, &TESTNET];

/// Serialized length of the key details shared by xpubs and xprivs: depth (1),
/// parent fingerprint (4), index (4), and chain code (32).
const KEY_DETAILS_LEN: usize = 1 + 4 + 4 + 32;

fn write_key_details<W>(writer: &mut W, key: &XKeyInfo) -> Result<usize, Bip32Error>
where
    W: std::io::Write,
{
    writer.write_all(&[key.depth])?;
    writer.write_all(&key.parent.0)?;
    writer.write_all(&key.index.to_be_bytes())?;
    writer.write_all(&key.chain_code.0)?;
    Ok(KEY_DETAILS_LEN)
}

fn read_depth<R>(reader: &mut R) -> Result<u8, Bip32Error>
where
    R: std::io::Read,
{
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_parent<R>(reader: &mut R) -> Result<KeyFingerprint, Bip32Error>
where
    R: std::io::Read,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(buf.into())
}

fn read_index<R>(reader: &mut R) -> Result<u32, Bip32Error>
where
    R: std::io::Read,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_chain_code<R>(reader: &mut R) -> Result<ChainCode, Bip32Error>
where
    R: std::io::Read,
{
    let mut chain_code = ChainCode([0u8; 32]);
    reader.read_exact(&mut chain_code.0)?;
    Ok(chain_code)
}

/// Read the four version bytes and return the hint and network of the first candidate whose
/// `lookup` recognizes them. Unrecognized bytes are passed to `unknown` to build the error.
fn read_version<R>(
    reader: &mut R,
    candidates: &[&'static NetworkVersions],
    lookup: fn(&NetworkVersions, u32) -> Option<Hint>,
    unknown: fn([u8; 4]) -> Bip32Error,
) -> Result<(Hint, &'static NetworkVersions), Bip32Error>
where
    R: std::io::Read,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    let version = u32::from_be_bytes(buf);
    candidates
        .iter()
        .find_map(|network| lookup(network, version).map(|hint| (hint, *network)))
        .ok_or_else(|| unknown(buf))
}

fn read_xpriv_body<R>(
    reader: &mut R,
    hint: Hint,
    network: &'static NetworkVersions,
) -> Result<XPriv, Bip32Error>
where
    R: std::io::Read,
{
    let depth = read_depth(reader)?;
    let parent = read_parent(reader)?;
    let index = read_index(reader)?;
    let chain_code = read_chain_code(reader)?;

    let mut buf = [0u8];
    reader.read_exact(&mut buf)?;
    if buf != [0] {
        return Err(Bip32Error::BadPadding(buf[0]));
    }

    let mut buf = Zeroizing::new([0u8; 32]);
    reader.read_exact(buf.as_mut())?;
    let key = ecdsa::SigningKey::from_slice(buf.as_ref())?;

    Ok(XPriv {
        key,
        xkey_info: XKeyInfo {
            depth,
            parent,
            index,
            chain_code,
            hint,
            network,
        },
    })
}

fn read_xpub_body<R>(
    reader: &mut R,
    hint: Hint,
    network: &'static NetworkVersions,
) -> Result<XPub, Bip32Error>
where
    R: std::io::Read,
{
    let depth = read_depth(reader)?;
    let parent = read_parent(reader)?;
    let index = read_index(reader)?;
    let chain_code = read_chain_code(reader)?;

    let mut buf = [0u8; 33];
    reader.read_exact(&mut buf)?;
    let key = ecdsa::VerifyingKey::from_sec1_bytes(&buf)?;

    Ok(XPub {
        key,
        xkey_info: XKeyInfo {
            depth,
            parent,
            index,
            chain_code,
            hint,
            network,
        },
    })
}

fn read_xpriv_from<R>(
    reader: &mut R,
    candidates: &[&'static NetworkVersions],
) -> Result<XPriv, Bip32Error>
where
    R: std::io::Read,
{
    let (hint, network) = read_version(
        reader,
        candidates,
        NetworkVersions::priv_hint,
        Bip32Error::BadXPrivVersionBytes,
    )?;
    read_xpriv_body(reader, hint, network)
}

fn read_xpub_from<R>(
    reader: &mut R,
    candidates: &[&'static NetworkVersions],
) -> Result<XPub, Bip32Error>
where
    R: std::io::Read,
{
    let (hint, network) = read_version(
        reader,
        candidates,
        NetworkVersions::pub_hint,
        Bip32Error::BadXPubVersionBytes,
    )?;
    read_xpub_body(reader, hint, network)
}

impl XPriv {
    /// Serialize the xpriv to `std::io::Write`, using its network's version bytes.
    pub fn write<W>(&self, writer: &mut W) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
    {
        let version = self.xkey_info.network.priv_version(self.xkey_info.hint);
        let version_bytes = version.to_be_bytes();
        writer.write_all(&version_bytes)?;
        let details = write_key_details(writer, &self.xkey_info)?;
        let key_bytes = Zeroizing::new(self.key.to_bytes());
        writer.write_all(&[0])?;
        writer.write_all(&key_bytes)?;
        Ok(version_bytes.len() + details + 1 + key_bytes.len())
    }

    /// Read an xpriv from `std::io::Read`, accepting Bitcoin mainnet and testnet version bytes.
    /// The key remembers which network it was read with.
    pub fn read<R>(reader: &mut R) -> Result<Self, Bip32Error>
    where
        R: std::io::Read,
    {
        read_xpriv_from(reader, &KNOWN)
    }

    /// Read an xpriv from `std::io::Read`, accepting only `network`'s version bytes.
    pub fn read_with<R>(
        reader: &mut R,
        network: &'static NetworkVersions,
    ) -> Result<Self, Bip32Error>
    where
        R: std::io::Read,
    {
        read_xpriv_from(reader, &[network])
    }

    /// Serialize the xpriv to base58check, using its network's version bytes. The result is
    /// zeroized on drop.
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPriv};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    ///
    /// let xpriv = XPriv::from_base58(xpriv_str)?;
    /// assert_eq!(xpriv.to_base58().as_str(), xpriv_str);
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_base58(&self) -> Zeroizing<String> {
        let mut buf = SerializedXPriv([0u8; 78]);
        let written = self
            .write(&mut &mut buf.0[..])
            .expect("78-byte buffer fits an xpriv");
        debug_assert_eq!(written, buf.0.len());
        encode_b58_check(&buf.0)
    }

    /// Read an xpriv from a base58check string, accepting Bitcoin mainnet and testnet version
    /// bytes. The key remembers which network it was read with.
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPriv};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    ///
    /// let xpriv = XPriv::from_base58(xpriv_str)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_base58(s: &str) -> Result<Self, Bip32Error> {
        let data = decode_b58_check(s)?;
        Self::read(&mut &data[..])
    }

    /// Read an xpriv from a base58check string, accepting only `network`'s version bytes.
    pub fn from_base58_with(
        s: &str,
        network: &'static NetworkVersions,
    ) -> Result<Self, Bip32Error> {
        let data = decode_b58_check(s)?;
        Self::read_with(&mut &data[..], network)
    }
}

impl XPub {
    /// Serialize the xpub to `std::io::Write`, using its network's version bytes.
    pub fn write<W>(&self, writer: &mut W) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
    {
        let version = self.xkey_info.network.pub_version(self.xkey_info.hint);
        let version_bytes = version.to_be_bytes();
        writer.write_all(&version_bytes)?;
        let details = write_key_details(writer, &self.xkey_info)?;
        let key_bytes = self.key.to_sec1_bytes();
        writer.write_all(&key_bytes)?;
        Ok(version_bytes.len() + details + key_bytes.len())
    }

    /// Read an xpub from `std::io::Read`, accepting Bitcoin mainnet and testnet version bytes.
    /// The key remembers which network it was read with.
    pub fn read<R>(reader: &mut R) -> Result<Self, Bip32Error>
    where
        R: std::io::Read,
    {
        read_xpub_from(reader, &KNOWN)
    }

    /// Read an xpub from `std::io::Read`, accepting only `network`'s version bytes.
    pub fn read_with<R>(
        reader: &mut R,
        network: &'static NetworkVersions,
    ) -> Result<Self, Bip32Error>
    where
        R: std::io::Read,
    {
        read_xpub_from(reader, &[network])
    }

    /// Serialize the xpub to base58check, using its network's version bytes.
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPub};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpub_str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
    ///
    /// let xpub = XPub::from_base58(xpub_str)?;
    /// assert_eq!(xpub.to_base58(), xpub_str);
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_base58(&self) -> String {
        let mut buf = [0u8; 78];
        let written = self
            .write(&mut &mut buf[..])
            .expect("78-byte buffer fits an xpub");
        debug_assert_eq!(written, buf.len());
        encode_b58_check(&buf).to_string()
    }

    /// Read an xpub from a base58check string, accepting Bitcoin mainnet and testnet version
    /// bytes. The key remembers which network it was read with.
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPub};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpub_str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
    ///
    /// let xpub = XPub::from_base58(xpub_str)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_base58(s: &str) -> Result<Self, Bip32Error> {
        let data = decode_b58_check(s)?;
        Self::read(&mut &data[..])
    }

    /// Read an xpub from a base58check string, accepting only `network`'s version bytes.
    pub fn from_base58_with(
        s: &str,
        network: &'static NetworkVersions,
    ) -> Result<Self, Bip32Error> {
        let data = decode_b58_check(s)?;
        Self::read_with(&mut &data[..], network)
    }
}

/// Deserialize an [`XPriv`] on `network`, for use with `#[serde(deserialize_with)]`.
///
/// The blind `Deserialize` impl only knows mainnet and testnet. `deserialize_with` takes a path
/// and cannot pass `network`, so wrap this in a one-argument function:
///
/// ```
/// use coins_bip32::{enc::{NetworkVersions, deserialize_xpriv}, xkeys::XPriv};
/// use serde::{Deserialize, Deserializer};
/// use coins_bip32::primitives::Hint;
///
/// const LITECOIN: NetworkVersions = NetworkVersions {
///     priv_legacy: 0x019d_9cfe,
///     priv_compatibility: 0x01b2_6792,
///     priv_segwit: 0x04b2_430c,
///     pub_legacy: 0x019d_a462,
///     pub_compatibility: 0x01b2_6ef6,
///     pub_segwit: 0x04b2_4746,
/// };
///
/// fn litecoin_xpriv<'de, D: Deserializer<'de>>(d: D) -> Result<XPriv, D::Error> {
///     deserialize_xpriv(d, &LITECOIN)
/// }
///
/// #[derive(Deserialize)]
/// struct Wallet {
///     #[serde(deserialize_with = "litecoin_xpriv")]
///     key: XPriv,
/// }
///
/// let mut key = XPriv::root_from_seed(&[1u8; 32], Some(Hint::Legacy)).unwrap();
/// key.set_network(&LITECOIN);
/// let json = serde_json::json!({ "key": key.to_base58().as_str() }).to_string();
/// let wallet: Wallet = serde_json::from_str(&json).unwrap();
/// assert_eq!(wallet.key, key);
/// ```
pub fn deserialize_xpriv<'de, D: serde::Deserializer<'de>>(
    d: D,
    network: &'static NetworkVersions,
) -> Result<XPriv, D::Error> {
    let s: &str = serde::Deserialize::deserialize(d)?;
    XPriv::from_base58_with(s, network).map_err(serde::de::Error::custom)
}

/// Deserialize an [`XPub`] on `network`, for use with `#[serde(deserialize_with)]`.
///
/// The blind `Deserialize` impl only knows mainnet and testnet. `deserialize_with` takes a path
/// and cannot pass `network`, so wrap this in a one-argument function:
///
/// ```
/// use coins_bip32::{enc::{NetworkVersions, deserialize_xpub}, xkeys::{XPriv, XPub}};
/// use serde::{Deserialize, Deserializer};
/// use coins_bip32::primitives::Hint;
///
/// const LITECOIN: NetworkVersions = NetworkVersions {
///     priv_legacy: 0x019d_9cfe,
///     priv_compatibility: 0x01b2_6792,
///     priv_segwit: 0x04b2_430c,
///     pub_legacy: 0x019d_a462,
///     pub_compatibility: 0x01b2_6ef6,
///     pub_segwit: 0x04b2_4746,
/// };
///
/// fn litecoin_xpub<'de, D: Deserializer<'de>>(d: D) -> Result<XPub, D::Error> {
///     deserialize_xpub(d, &LITECOIN)
/// }
///
/// #[derive(Deserialize)]
/// struct Wallet {
///     #[serde(deserialize_with = "litecoin_xpub")]
///     key: XPub,
/// }
///
/// let mut key = XPriv::root_from_seed(&[1u8; 32], Some(Hint::Legacy)).unwrap().verify_key();
/// key.set_network(&LITECOIN);
/// let json = serde_json::json!({ "key": key.to_base58() }).to_string();
/// let wallet: Wallet = serde_json::from_str(&json).unwrap();
/// assert_eq!(wallet.key, key);
/// ```
pub fn deserialize_xpub<'de, D: serde::Deserializer<'de>>(
    d: D,
    network: &'static NetworkVersions,
) -> Result<XPub, D::Error> {
    let s: &str = serde::Deserialize::deserialize(d)?;
    XPub::from_base58_with(s, network).map_err(serde::de::Error::custom)
}

#[derive(serde::Deserialize)]
struct DerivedXPrivRepr<'a> {
    #[serde(borrow)]
    xpriv: &'a str,
    derivation: KeyDerivation,
}

#[derive(serde::Deserialize)]
struct DerivedXPubRepr<'a> {
    #[serde(borrow)]
    xpub: &'a str,
    derivation: KeyDerivation,
}

/// Deserialize a [`DerivedXPriv`] on `network`, for use with `#[serde(deserialize_with)]`.
///
/// The blind `Deserialize` impl only knows mainnet and testnet. `deserialize_with` takes a path
/// and cannot pass `network`, so wrap this in a one-argument function:
///
/// ```
/// use coins_bip32::{
///     derived::DerivedXPriv,
///     enc::{NetworkVersions, deserialize_derived_xpriv},
/// };
/// use serde::{Deserialize, Deserializer};
/// use coins_bip32::primitives::Hint;
///
/// const LITECOIN: NetworkVersions = NetworkVersions {
///     priv_legacy: 0x019d_9cfe,
///     priv_compatibility: 0x01b2_6792,
///     priv_segwit: 0x04b2_430c,
///     pub_legacy: 0x019d_a462,
///     pub_compatibility: 0x01b2_6ef6,
///     pub_segwit: 0x04b2_4746,
/// };
///
/// fn litecoin_derived_xpriv<'de, D: Deserializer<'de>>(d: D) -> Result<DerivedXPriv, D::Error> {
///     deserialize_derived_xpriv(d, &LITECOIN)
/// }
///
/// #[derive(Deserialize)]
/// struct Wallet {
///     #[serde(deserialize_with = "litecoin_derived_xpriv")]
///     key: DerivedXPriv,
/// }
///
/// let mut key = DerivedXPriv::root_from_seed(&[1u8; 32], Some(Hint::Legacy)).unwrap();
/// key.set_network(&LITECOIN);
/// let json = serde_json::json!({ "key": &key }).to_string();
/// let wallet: Wallet = serde_json::from_str(&json).unwrap();
/// assert_eq!(
///     serde_json::to_string(&wallet.key).unwrap(),
///     serde_json::to_string(&key).unwrap()
/// );
/// ```
pub fn deserialize_derived_xpriv<'de, D: serde::Deserializer<'de>>(
    d: D,
    network: &'static NetworkVersions,
) -> Result<DerivedXPriv, D::Error> {
    let repr: DerivedXPrivRepr = serde::Deserialize::deserialize(d)?;
    let xpriv = XPriv::from_base58_with(repr.xpriv, network).map_err(serde::de::Error::custom)?;
    Ok(DerivedXPriv::new(xpriv, repr.derivation))
}

/// Deserialize a [`DerivedXPub`] on `network`, for use with `#[serde(deserialize_with)]`.
///
/// The blind `Deserialize` impl only knows mainnet and testnet. `deserialize_with` takes a path
/// and cannot pass `network`, so wrap this in a one-argument function:
///
/// ```
/// use coins_bip32::{
///     derived::{DerivedXPriv, DerivedXPub},
///     enc::{NetworkVersions, deserialize_derived_xpub},
/// };
/// use serde::{Deserialize, Deserializer};
/// use coins_bip32::primitives::Hint;
///
/// const LITECOIN: NetworkVersions = NetworkVersions {
///     priv_legacy: 0x019d_9cfe,
///     priv_compatibility: 0x01b2_6792,
///     priv_segwit: 0x04b2_430c,
///     pub_legacy: 0x019d_a462,
///     pub_compatibility: 0x01b2_6ef6,
///     pub_segwit: 0x04b2_4746,
/// };
///
/// fn litecoin_derived_xpub<'de, D: Deserializer<'de>>(d: D) -> Result<DerivedXPub, D::Error> {
///     deserialize_derived_xpub(d, &LITECOIN)
/// }
///
/// #[derive(Deserialize)]
/// struct Wallet {
///     #[serde(deserialize_with = "litecoin_derived_xpub")]
///     key: DerivedXPub,
/// }
///
/// let mut key = DerivedXPriv::root_from_seed(&[1u8; 32], Some(Hint::Legacy)).unwrap().verify_key();
/// key.set_network(&LITECOIN);
/// let json = serde_json::json!({ "key": &key }).to_string();
/// let wallet: Wallet = serde_json::from_str(&json).unwrap();
/// assert_eq!(wallet.key, key);
/// ```
pub fn deserialize_derived_xpub<'de, D: serde::Deserializer<'de>>(
    d: D,
    network: &'static NetworkVersions,
) -> Result<DerivedXPub, D::Error> {
    let repr: DerivedXPubRepr = serde::Deserialize::deserialize(d)?;
    let xpub = XPub::from_base58_with(repr.xpub, network).map_err(serde::de::Error::custom)?;
    Ok(DerivedXPub::new(xpub, repr.derivation))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_b58_check_rejects_short_input() {
        for len in 0..4 {
            let s = bs58::encode(vec![1u8; len]).into_string();
            assert!(matches!(
                decode_b58_check(&s),
                Err(Bip32Error::BadB58Checksum)
            ));
        }
    }

    #[test]
    fn b58_check_round_trip() {
        let payload = b"hello world";
        let encoded = encode_b58_check(payload);
        assert_eq!(decode_b58_check(&encoded).unwrap().as_slice(), payload);
    }

    /// Accepts one byte per `write` call, so a writer that trusts a single `write` truncates.
    struct ShortWriter(Vec<u8>);

    impl std::io::Write for ShortWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(byte) = buf.first() {
                self.0.push(*byte);
                Ok(1)
            } else {
                Ok(0)
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `$write` against a `Vec` and against a `ShortWriter`, and asserts that both end up
    /// with the same bytes and report the full length.
    macro_rules! assert_short_write_matches {
        ($write:expr) => {{
            let mut full = Vec::new();
            let mut short = ShortWriter(Vec::new());
            let full_len = $write(&mut full).unwrap();
            let short_len = $write(&mut short).unwrap();
            assert_eq!(full_len, full.len());
            assert_eq!(short_len, full_len);
            assert_eq!(short.0, full);
        }};
    }

    #[test]
    fn writers_handle_short_writes() {
        let xpriv = XPriv::root_from_seed(&[7u8; 32], None).unwrap();
        let xpub = xpriv.verify_key();

        assert_short_write_matches!(|w| xpriv.write(w));
        assert_short_write_matches!(|w| xpub.write(w));
    }
}

#[cfg(test)]
#[path = "../ai-tests/enc.rs"]
mod ai_tests;
