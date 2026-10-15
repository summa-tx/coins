use coins_core::hashes::{Digest, Hash256};
use k256::ecdsa;
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    primitives::{ChainCode, Hint, KeyFingerprint, XKeyInfo},
    xkeys::{XPriv, XPub},
    Bip32Error,
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

/// Serialized length of the key details shared by xpubs and xprivs: depth (1), parent
/// fingerprint (4), index (4), and chain code (32).
const KEY_DETAILS_LEN: usize = 1 + 4 + 4 + 32;

/// Bip32/49/84 encoder
pub trait XKeyEncoder: sealed::Sealed {
    #[doc(hidden)]
    fn write_key_details<K, W>(writer: &mut W, key: &K) -> Result<usize, Bip32Error>
    where
        K: AsRef<XKeyInfo>,
        W: std::io::Write,
    {
        let key = key.as_ref();
        writer.write_all(&[key.depth])?;
        writer.write_all(&key.parent.0)?;
        writer.write_all(&key.index.to_be_bytes())?;
        writer.write_all(&key.chain_code.0)?;
        Ok(KEY_DETAILS_LEN)
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
        let mut chain_code = ChainCode([0u8; 32]);
        reader.read_exact(&mut chain_code.0)?;
        Ok(chain_code)
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
        let mut buf = SerializedXPriv([0u8; 78]);
        let written = Self::write_xpriv(&mut &mut buf.0[..], k)?;
        debug_assert_eq!(written, buf.0.len());
        Ok(encode_b58_check(&buf.0))
    }

    /// Serialize an XPub to base58
    fn xpub_to_base58<K>(k: &K) -> Result<String, Bip32Error>
    where
        K: AsRef<XPub>,
    {
        let mut v: Vec<u8> = vec![];
        Self::write_xpub(&mut v, k)?;
        Ok(encode_b58_check(&v).to_string())
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
        let data = decode_b58_check(s)?;
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

mod sealed {
    /// Prevents downstream implementations of [`XKeyEncoder`](super::XKeyEncoder), so the
    /// serialization lengths assumed by its provided methods always hold.
    pub trait Sealed {}
}

impl<P: NetworkParams> sealed::Sealed for BitcoinEncoder<P> {}

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
        let version_bytes = version.to_be_bytes();
        writer.write_all(&version_bytes)?;
        let details = Self::write_key_details(writer, key.as_ref())?;
        let key_bytes = key.as_ref().key.to_sec1_bytes();
        writer.write_all(&key_bytes)?;
        Ok(version_bytes.len() + details + key_bytes.len())
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
        let version_bytes = version.to_be_bytes();
        writer.write_all(&version_bytes)?;
        let details = Self::write_key_details(writer, key.as_ref())?;
        let key_bytes = Zeroizing::new(key.as_ref().key.to_bytes());
        writer.write_all(&[0])?;
        writer.write_all(&key_bytes)?;
        Ok(version_bytes.len() + details + 1 + key_bytes.len())
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
    use crate::path::{DerivationPath, KeyDerivation};
    use coins_core::ser::ByteFormat;

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
        let derivation = KeyDerivation {
            root: KeyFingerprint([1, 2, 3, 4]),
            path: DerivationPath::from(vec![44, 0, 1]),
        };

        assert_short_write_matches!(|w| MainnetEncoder::write_xpriv(w, &xpriv));
        assert_short_write_matches!(|w| MainnetEncoder::write_xpub(w, &xpub));
        assert_short_write_matches!(|w| derivation.root.write_to(w));
        assert_short_write_matches!(|w| derivation.write_to(w));
    }
}
