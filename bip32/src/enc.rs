use std::marker::{PhantomData};

use bs58;
use bitcoin_spv::btcspv::{hash256};

use crate::{
    Bip32Error,
    xkeys::{ChainCode, KeyFingerprint, Hint, XKey, XPriv, XPub},
    backend::{Secp256k1Backend, ScalarSerialize, PointSerialize},
};

/// Decode a bytevector from a base58 check string
pub fn decode_b58_check(s: &str) -> Result<Vec<u8>, Bip32Error> {
    let data: Vec<u8> = bs58::decode(s).into_vec()?;
    let idx = data.len() - 4;
    let payload = &data[..idx];
    let checksum = &data[idx..];

    let mut     expected = [0u8; 4];
    expected.copy_from_slice(&hash256(&[&payload[..]])[..4]);
    if expected != checksum {
        Err(Bip32Error::BadB58Checksum)
    } else {
        Ok(payload.to_vec())
    }
}

/// Encode a vec into a base58 check String
pub fn encode_b58_check(v: &[u8]) -> String {
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash256(&[&v[..]])[..4]);

    let mut data = v.to_vec();
    data.extend(&checksum);

    bs58::encode(data).into_string()
}

/// Contains network-specific serialization information
pub trait NetworkParams {
    /// The Bip32 privkey version bytes
    const PRIV_VERSION: u32;
    /// The Bip49 privkey version bytes
    const BIP49_PRIV_VERSION: u32;
    /// The Bip84 pubkey version bytes
    const BIP84_PRIV_VERSION: u32;
    /// The Bip32 pubkey version bytes
    const PUB_VERSION: u32;
    /// The Bip49 pubkey version bytes
    const BIP49_PUB_VERSION: u32;
    /// The Bip84 pubkey version bytes
    const BIP84_PUB_VERSION: u32;
}

/// Bip32/49/84 encoder
pub trait Encoder<P: NetworkParams> {
    #[doc(hidden)]
    fn write_key_details<K, W>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        K: XKey,
        W: std::io::Write
    {
        let mut written = writer.write(&[key.depth()])?;
        written += writer.write(&key.parent().0)?;
        written += writer.write(&key.index().to_be_bytes())?;
        written += writer.write(&key.chain_code().0)?;
        Ok(written)
    }

    /// Serialize the xpub to `std::io::Write`
    fn write_xpub<W, T>(writer: &mut W, key: &XPub<T>) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
        T: Secp256k1Backend
    {
        let version = match key.hint() {
            Hint::Legacy => P::PUB_VERSION,
            Hint::Compatibility => P::BIP49_PUB_VERSION,
            Hint::SegWit => P::BIP84_PUB_VERSION,
        };
        let mut written = writer.write(&version.to_be_bytes())?;
        written += Self::write_key_details(writer, key)?;
        written += writer.write(&key.compressed_pubkey())?;
        Ok(written)
    }

    /// Serialize the xpriv to `std::io::Write`
    fn write_xpriv<W, T>(writer: &mut W, key: &XPriv<T>) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
        T: Secp256k1Backend
    {
        let version = match key.hint() {
            Hint::Legacy => P::PRIV_VERSION,
            Hint::Compatibility => P::BIP49_PRIV_VERSION,
            Hint::SegWit => P::BIP84_PRIV_VERSION,
        };
        let mut written = writer.write(&version.to_be_bytes())?;
        written += Self::write_key_details(writer, key)?;
        written += writer.write(&[0])?;
        written += writer.write(&key.secret_key())?;
        Ok(written)
    }

    #[doc(hidden)]
    fn read_depth<R>(reader: &mut R) -> Result<u8, Bip32Error>
    where
        R: std::io::Read
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[doc(hidden)]
    fn read_parent<R>(reader: &mut R) -> Result<KeyFingerprint, Bip32Error>
    where
        R: std::io::Read
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(buf.into())
    }

    #[doc(hidden)]
    fn read_index<R>(reader: &mut R) -> Result<u32, Bip32Error>
    where
        R: std::io::Read
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    #[doc(hidden)]
    fn read_chain_code<R>(reader: &mut R) -> Result<ChainCode, Bip32Error>
    where
        R: std::io::Read
    {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(buf.into())
    }

    /// Attempt to instantiate an `XPriv` from a `std::io::Read`
    fn read_xpriv<'a, R, T>(reader: &mut R, backend: Option<&'a T>) -> Result<XPriv<'a, T>, Bip32Error>
    where
        R: std::io::Read,
        T: Secp256k1Backend
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let version_bytes = u32::from_be_bytes(buf);

        // Can't use associated constants in matches :()
        let hint = if version_bytes == P::PRIV_VERSION {
            Hint::Legacy
        } else if version_bytes == P::BIP49_PRIV_VERSION {
            Hint::Compatibility
        } else if version_bytes == P::BIP84_PRIV_VERSION {
            Hint::SegWit
        } else {
            return Err(Bip32Error::BadXPrivVersionBytes(buf));
        };

        let depth = Self::read_depth(reader)?;
        let parent = Self::read_parent(reader)?;
        let index = Self::read_index(reader)?;
        let chain_code = Self::read_chain_code(reader)?;

        let mut buf = [0u8];
        reader.read_exact(&mut buf)?;
        if buf != [0] {
            return Err(Bip32Error::BadPadding(buf[0]))
        }

        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        let key = T::Privkey::from_array(buf);

        Ok(XPriv::new(depth, parent, index, key, chain_code, hint, backend))
    }

    /// Attempt to instantiate an `XPriv` from a `std::io::Read`
    fn read_xpub<'a, R, T>(reader: &mut R, backend: Option<&'a T>) -> Result<XPub<'a, T>, Bip32Error>
    where
        R: std::io::Read,
        T: Secp256k1Backend
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let version_bytes = u32::from_be_bytes(buf);

        // Can't use associated constants in matches :()
        let hint = if version_bytes == P::PUB_VERSION {
            Hint::Legacy
        } else if version_bytes == P::BIP49_PUB_VERSION {
            Hint::Compatibility
        } else if version_bytes == P::BIP84_PUB_VERSION {
            Hint::SegWit
        } else {
            return Err(Bip32Error::BadXPrivVersionBytes(buf));
        };

        let depth = Self::read_depth(reader)?;
        let parent = Self::read_parent(reader)?;
        let index = Self::read_index(reader)?;
        let chain_code = Self::read_chain_code(reader)?;

        let mut buf = [0u8; 33];
        reader.read_exact(&mut buf)?;
        let key = T::Pubkey::from_array(buf)?;

        Ok(XPub::new(depth, parent, index, key, chain_code, hint, backend))
    }

    /// Serialize an XPriv to base58
    fn xpriv_to_base58<'a, T>(k: &XPriv<'a, T>) -> Result<String, Bip32Error>
    where
        T: Secp256k1Backend
    {
        let mut v: Vec<u8> = vec![];
        Self::write_xpriv(&mut v, k)?;
        Ok(encode_b58_check(&v))
    }

    /// Serialize an XPub to base58
    fn xpub_to_base58<'a, T>(k: &XPub<'a, T>) -> Result<String, Bip32Error>
    where
        T: Secp256k1Backend
    {
        let mut v: Vec<u8> = vec![];
        Self::write_xpub(&mut v, k)?;
        Ok(encode_b58_check(&v))
    }

    /// Attempt to read an XPriv from a b58check string
    fn xpriv_from_base58<'a, T>(s: &str, backend: Option<&'a T>) -> Result<XPriv<'a, T>, Bip32Error>
    where
        T: Secp256k1Backend
    {
        let data = decode_b58_check(s)?;
        Self::read_xpriv(&mut &data[..], backend)
    }

    /// Attempt to read an XPub from a b58check string
    fn xpub_from_base58<'a, T>(s: &str, backend: Option<&'a T>) -> Result<XPub<'a, T>, Bip32Error>
    where
        T: Secp256k1Backend
    {
        let data = decode_b58_check(s)?;
        Self::read_xpub(&mut &data[..], backend)
    }
}

macro_rules! params {
    (
        $(#[$outer:meta])*
        $name:ident{
            bip32: $bip32:expr,
            bip49: $bip49:expr,
            bip84: $bip84:expr,
            bip32_pub: $bip32pub:expr,
            bip49_pub: $bip49pub:expr,
            bip84_pub: $bip84pub:expr
        }
    ) => {
        $(#[$outer])*
        pub struct $name;

        impl NetworkParams for $name {
            const PRIV_VERSION: u32 = $bip32;
            const BIP49_PRIV_VERSION: u32 = $bip49;
            const BIP84_PRIV_VERSION: u32 = $bip84;
            const PUB_VERSION: u32 = $bip32pub;
            const BIP49_PUB_VERSION: u32 = $bip49pub;
            const BIP84_PUB_VERSION: u32 = $bip84pub;
        }
    }
}

params!(
    /// Mainnet encoding param
    Main{
        bip32: 0x0488_ADE4,
        bip49: 0x049d_7878,
        bip84: 0x04b2_430c,
        bip32_pub: 0x0488_B21E,
        bip49_pub: 0x049d_7cb2,
        bip84_pub: 0x04b2_4746
    }
);

params!(
    /// Testnet encoding param
    Test{
        bip32: 0x0435_8394,
        bip49: 0x044a_4e28,
        bip84: 0x045f_18bc,
        bip32_pub: 0x0435_87CF,
        bip49_pub: 0x044a_5262,
        bip84_pub: 0x045f_1cf6
    }
);

/// Parameterizable Bitcoin encoder
#[derive(Debug, Clone)]
pub struct BitcoinEncoder<P: NetworkParams>(PhantomData<*const P>);

impl<P: NetworkParams> Encoder<P> for BitcoinEncoder<P> {}

/// Encoder for Mainnet xkeys
pub type MainnetEncoder = BitcoinEncoder<Main>;
/// Encoder for Testnet xkeys
pub type TestnetEncoder = BitcoinEncoder<Test>;
