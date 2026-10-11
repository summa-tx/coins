use coins_core::hashes::{Digest, Hash256};
use k256::ecdsa;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    primitives::{ChainCode, Hint, KeyFingerprint, XKeyInfo},
    xkeys::{XPriv, XPub},
    Bip32Error,
};

/// Decode a bytevector from a base58 check string
///
/// Intermediate buffers are zeroized, as the payload may be secret.
pub fn decode_b58_check(s: &str) -> Result<Vec<u8>, Bip32Error> {
    let mut data: Vec<u8> = bs58::decode(s).into_vec()?;
    let Some((payload, checksum)) = data.split_last_chunk::<4>() else {
        return Err(Bip32Error::BadB58Checksum);
    };
    let len = payload.len();

    if Hash256::digest(payload)[..4] != checksum[..] {
        data.zeroize();
        return Err(Bip32Error::BadB58Checksum);
    }

    data.truncate(len);
    Ok(data)
}

/// Encode a vec into a base58 check String
///
/// Intermediate buffers are zeroized, as the payload may be secret.
pub fn encode_b58_check(v: &[u8]) -> String {
    let digest = &Hash256::digest(v);

    let mut data = Zeroizing::new(Vec::with_capacity(v.len() + 4));
    data.extend_from_slice(v);
    data.extend_from_slice(&digest[..4]);

    bs58::encode(&*data).into_string()
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

params!(
    /// Mainnet encoding param
    Main {
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
    Test {
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
pub struct BitcoinEncoder<P: NetworkParams>(PhantomData<fn(P) -> P>);

/// XKeyEncoder for Mainnet xkeys
pub type MainnetEncoder = BitcoinEncoder<Main>;
/// XKeyEncoder for Testnet xkeys
pub type TestnetEncoder = BitcoinEncoder<Test>;

/// Bip32/49/84 encoder
pub trait XKeyEncoder {
    #[doc(hidden)]
    fn write_key_details<K, W>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        K: AsRef<XKeyInfo>,
        W: std::io::Write,
    {
        let key = key.as_ref();
        let mut written = writer.write(&[key.depth])?;
        written += writer.write(&key.parent.0)?;
        written += writer.write(&key.index.to_be_bytes())?;
        written += writer.write(&key.chain_code.0)?;
        Ok(written)
    }

    /// Serialize the xpub to `std::io::Write`
    fn write_xpub<W, K>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
        K: AsRef<XPub>;

    /// Serialize the xpriv to `std::io::Write`
    fn write_xpriv<W, K>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
        K: AsRef<XPriv>;

    #[doc(hidden)]
    fn read_depth<R>(reader: &mut R) -> Result<u8, Bip32Error>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[doc(hidden)]
    fn read_parent<R>(reader: &mut R) -> Result<KeyFingerprint, Bip32Error>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(buf.into())
    }

    #[doc(hidden)]
    fn read_index<R>(reader: &mut R) -> Result<u32, Bip32Error>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    #[doc(hidden)]
    fn read_chain_code<R>(reader: &mut R) -> Result<ChainCode, Bip32Error>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(buf.into())
    }

    #[doc(hidden)]
    fn read_xpriv_body<R>(reader: &mut R, hint: Hint) -> Result<XPriv, Bip32Error>
    where
        R: std::io::Read,
    {
        let depth = Self::read_depth(reader)?;
        let parent = Self::read_parent(reader)?;
        let index = Self::read_index(reader)?;
        let chain_code = Self::read_chain_code(reader)?;

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
            },
        })
    }

    #[doc(hidden)]
    // Can be used for unhealthy but sometimes-desiable behavior. E.g. accepting an xpriv from any
    // network.
    fn read_xpriv_without_network<R>(reader: &mut R) -> Result<XPriv, Bip32Error>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;

        Self::read_xpriv_body(reader, Hint::Legacy)
    }

    /// Attempt to instantiate an `XPriv` from a `std::io::Read`
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPriv, enc::{XKeyEncoder, MainnetEncoder}};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
    ///
    /// let xpriv: XPriv = MainnetEncoder::xpriv_from_base58(&xpriv_str)?;
    /// # Ok(())
    /// # }
    /// ```
    fn read_xpriv<R>(reader: &mut R) -> Result<XPriv, Bip32Error>
    where
        R: std::io::Read;

    #[doc(hidden)]
    fn read_xpub_body<R>(reader: &mut R, hint: Hint) -> Result<XPub, Bip32Error>
    where
        R: std::io::Read,
    {
        let depth = Self::read_depth(reader)?;
        let parent = Self::read_parent(reader)?;
        let index = Self::read_index(reader)?;
        let chain_code = Self::read_chain_code(reader)?;

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
            },
        })
    }

    #[doc(hidden)]
    // Can be used for unhealthy but sometimes-desiable behavior. E.g. accepting an xpub from any
    // network.
    fn read_xpub_without_network<R>(reader: &mut R) -> Result<XPub, Bip32Error>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;

        Self::read_xpub_body(reader, Hint::Legacy)
    }

    /// Attempt to instantiate an `XPub` from a `std::io::Read`
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPub, enc::{XKeyEncoder, MainnetEncoder}};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpub_str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y".to_owned();
    ///
    /// let xpub: XPub = MainnetEncoder::xpub_from_base58(&xpub_str)?;
    /// # Ok(())
    /// # }
    /// ```
    fn read_xpub<R>(reader: &mut R) -> Result<XPub, Bip32Error>
    where
        R: std::io::Read;

    /// Serialize an XPriv to base58. The result is zeroized on drop.
    fn xpriv_to_base58<K>(k: &K) -> Result<Zeroizing<String>, Bip32Error>
    where
        K: AsRef<XPriv>,
    {
        // Sized up front so the key is never left behind by a reallocation.
        let mut v = Zeroizing::new(Vec::with_capacity(78));
        Self::write_xpriv(&mut *v, k)?;
        Ok(Zeroizing::new(encode_b58_check(&v)))
    }

    /// Serialize an XPub to base58
    fn xpub_to_base58<K>(k: &K) -> Result<String, Bip32Error>
    where
        K: AsRef<XPub>,
    {
        let mut v: Vec<u8> = vec![];
        Self::write_xpub(&mut v, k)?;
        Ok(encode_b58_check(&v))
    }

    /// Attempt to read an XPriv from a b58check string.
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPriv, enc::{XKeyEncoder, MainnetEncoder}};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpriv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_owned();
    ///
    /// let xpriv: XPriv = MainnetEncoder::xpriv_from_base58(&xpriv_str)?;
    /// # Ok(())
    /// # }
    /// ```
    fn xpriv_from_base58(s: &str) -> Result<XPriv, Bip32Error>
where {
        let data = Zeroizing::new(decode_b58_check(s)?);
        Self::read_xpriv(&mut &data[..])
    }

    /// Attempt to read an XPub from a b58check string
    ///
    /// ```
    /// use coins_bip32::{Bip32Error, xkeys::XPub, enc::{XKeyEncoder, MainnetEncoder}};
    /// # fn main() -> Result<(), Bip32Error> {
    /// let xpub_str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y".to_owned();
    ///
    /// let xpub: XPub = MainnetEncoder::xpub_from_base58(&xpub_str)?;
    /// # Ok(())
    /// # }
    /// ```
    fn xpub_from_base58(s: &str) -> Result<XPub, Bip32Error>
where {
        let data = decode_b58_check(s)?;
        Self::read_xpub(&mut &data[..])
    }
}

impl<P: NetworkParams> XKeyEncoder for BitcoinEncoder<P> {
    /// Serialize the xpub to `std::io::Write`
    fn write_xpub<W, K>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
        K: AsRef<XPub>,
    {
        let version = match key.as_ref().xkey_info.hint {
            Hint::Legacy => P::PUB_VERSION,
            Hint::Compatibility => P::BIP49_PUB_VERSION,
            Hint::SegWit => P::BIP84_PUB_VERSION,
        };
        let mut written = writer.write(&version.to_be_bytes())?;
        written += Self::write_key_details(writer, key.as_ref())?;
        written += writer.write(key.as_ref().key.to_sec1_bytes().as_ref())?;
        Ok(written)
    }

    /// Serialize the xpriv to `std::io::Write`
    fn write_xpriv<W, K>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        W: std::io::Write,
        K: AsRef<XPriv>,
    {
        let version = match key.as_ref().xkey_info.hint {
            Hint::Legacy => P::PRIV_VERSION,
            Hint::Compatibility => P::BIP49_PRIV_VERSION,
            Hint::SegWit => P::BIP84_PRIV_VERSION,
        };
        let mut written = writer.write(&version.to_be_bytes())?;
        written += Self::write_key_details(writer, key.as_ref())?;
        written += writer.write(&[0])?;
        written += writer.write(&Zeroizing::new(key.as_ref().key.to_bytes()))?;
        Ok(written)
    }

    fn read_xpriv<R>(reader: &mut R) -> Result<XPriv, Bip32Error>
    where
        R: std::io::Read,
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
        Self::read_xpriv_body(reader, hint)
    }

    fn read_xpub<R>(reader: &mut R) -> Result<XPub, Bip32Error>
    where
        R: std::io::Read,
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
            return Err(Bip32Error::BadXPubVersionBytes(buf));
        };
        Self::read_xpub_body(reader, hint)
    }
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
        assert_eq!(decode_b58_check(&encoded).unwrap(), payload);
    }
}
