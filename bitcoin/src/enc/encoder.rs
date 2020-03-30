//! Defines parameterized Bitcoin encoders for Mainnet, Testnet, and Signet.

use std::{
    marker::{PhantomData},
};

use riemann_core::{
    enc::{AddressEncoder},
    types::{
        primitives::{PrefixVec},
    },
};

use crate::{
    bases::{
        EncodingError,
        EncodingResult,
        encode_base58,
        decode_base58,
        encode_bech32,
        decode_bech32,
    },
    script::{ScriptPubkey, ScriptType},
};


/// The available Bitcoin Address types, implemented as a type enum around strings.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Address {
    /// Legacy Pay to Pubkeyhash
    PKH(String),
    /// Legacy Pay to Scripthash
    SH(String),
    /// Witness Pay to Pubkeyhash
    WPKH(String),
    /// Witness Pay to Scripthash
    WSH(String),
}

impl Address {
    /// Get a clone of the string underlying the address type.
    pub fn as_string(&self) -> String {
        match &self {
            Address::PKH(s) => s.clone(),
            Address::SH(s) => s.clone(),
            Address::WPKH(s) => s.clone(),
            Address::WSH(s) => s.clone(),
        }
    }
}

/// NetworkParams holds the encoding paramteres for a bitcoin-like network. Currently this is
/// composed of the address version bytes for Legacy PKH and SH addresses, and the bech32
/// human-readable prefix for witness addresses.
pub trait NetworkParams {
    /// The BECH32 HRP. "bc" for mainnet.
    const HRP: &'static str;
    /// The Legacy PKH base58check version byte. 0x00 for mainnet.
    const PKH_VERSION: u8;
    /// The Legacy SH base58check version byte. 0x05 for mainnet.
    const SH_VERSION: u8;
}


/// The standard encoder for Bitcoin networks. Parameterized by a `NetworkParams` type.
#[derive(Debug, Clone)]
pub struct BitcoinEncoder<P: NetworkParams>(PhantomData<P>);

impl<P: NetworkParams> AddressEncoder for BitcoinEncoder<P> {
    type Address = Address;
    type Error = EncodingError;
    type RecipientIdentifier = ScriptPubkey;

    fn encode_address(s: &ScriptPubkey) -> EncodingResult<Address> {
        match s.determine_type() {
            ScriptType::PKH => {
                // s.items contains the op codes. we want only the pkh
                Ok(Address::PKH(encode_base58(P::PKH_VERSION, &s.items()[4..24])))
            },
            ScriptType::SH => {
                // s.items contains the op codes. we want only the sh
                Ok(Address::SH(encode_base58(P::SH_VERSION, &s.items()[3..23])))
            },
            ScriptType::WSH => {
                Ok(Address::WSH(encode_bech32(P::HRP, &s.items())?))
            }
            ScriptType::WPKH => {
                Ok(Address::WPKH(encode_bech32(P::HRP, &s.items())?))
            }
            ScriptType::NonStandard => {
                Err(EncodingError::UnknownScriptType)
            }
        }
    }

    fn decode_address(addr: &Address) -> EncodingResult<ScriptPubkey> {
        match &addr {
            Address::PKH(s) => {
                decode_base58(P::PKH_VERSION, s).map(|v| v.into())
            },
            Address::SH(s) => {
                decode_base58(P::SH_VERSION, s).map(|v| v.into())
            },
            Address::WPKH(s) | Address::WSH(s) => {
                decode_bech32(P::HRP, &s).map(|v| v.into())
            }
        }
    }

    fn wrap_string(string: &str) -> EncodingResult<Address> {
        let s = string.to_owned();
        if s.starts_with(P::HRP) {
            let result = decode_bech32(P::HRP, &s)?;
            match result.len() {
                22 => Ok(Address::WPKH(s)),
                34 => Ok(Address::WSH(s)),
                _ => Err(EncodingError::UnknownScriptType)
            }
        } else if decode_base58(P::PKH_VERSION, &s).is_ok() {
                Ok(Address::PKH(s))
        } else if decode_base58(P::SH_VERSION, &s).is_ok() {
                Ok(Address::SH(s))
        } else {
            Err(EncodingError::UnknownScriptType)
        }
    }
}

/// A param struct for Bitcoin Mainnet
#[derive(Debug, Clone)]
pub struct Main;

impl NetworkParams for Main {
    const HRP: &'static str = "bc";
    const PKH_VERSION: u8 = 0x00;
    const SH_VERSION: u8 = 0x05;
}

/// A param struct for Bitcoin Tesnet
#[derive(Debug, Clone)]
pub struct Test;

impl NetworkParams for Test {
    const HRP: &'static str = "tb";
    const PKH_VERSION: u8 = 0x6f;
    const SH_VERSION: u8 = 0xc4;
}

/// A param struct for Bitcoin Signet
#[derive(Debug, Clone)]
pub struct Sig;

impl NetworkParams for Sig {
    const HRP: &'static str = "sb";
    const PKH_VERSION: u8 = 0x7d;
    const SH_VERSION: u8 = 0x57;
}

/// An encoder for Bitcoin Mainnet
pub type MainnetEncoder = BitcoinEncoder<Main>;

/// An encoder for Bitcoin Tesnet
pub type TestnetEncoder = BitcoinEncoder<Test>;

/// An encoder for Bitcoin Signet
pub type SignetEncoder = BitcoinEncoder<Sig>;


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_wraps_address_strings() {
        let cases = [
            ("bc1qza7dfgl2q83cf68fqkkdd754qx546h4u9vd9tg".to_owned(), Address::WPKH("bc1qza7dfgl2q83cf68fqkkdd754qx546h4u9vd9tg".to_owned())),
            ("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej".to_owned(), Address::WSH("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej".to_owned())),
            ("1AqE7oGF1EUoJviX1uuYrwpRBdEBTuGhES".to_owned(), Address::PKH("1AqE7oGF1EUoJviX1uuYrwpRBdEBTuGhES".to_owned())),
            ("3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2".to_owned(), Address::SH("3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2".to_owned())),
        ];
        for case in cases.iter() {
            assert_eq!(
                MainnetEncoder::wrap_string(&case.0).unwrap(),
                case.1
            );
        }
    }
}
