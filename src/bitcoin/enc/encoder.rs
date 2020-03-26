use std::{
    marker::{PhantomData},
};

use crate::{
    bitcoin::{
        bases::{
            EncodingError,
            EncodingResult,
            encode_base58,
            decode_base58,
            encode_bech32,
            decode_bech32,
        },
        script::{Script, ScriptType},
    },
    enc::{
        encoder::{AddressEncoder},
    },
    types::{
        primitives::{PrefixVec},
    },
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

/// NetworkParams holds the encoding paramteres for a network. Currently this is composed of the
/// address version bytes for Legacy PKH and SH addresses, and the bech32 human-readable prefix
/// for witness addresses.
pub trait NetworkParams {
    /// The BECH32 HRP. "bc" for mainnet.
    const HRP: &'static str;
    /// The Legacy PKH base58check version byte. 0x00 for mainnet.
    const PKH_VERSION: u8;
    /// The Legacy SH base58check version byte. 0x05 for mainnet.
    const SH_VERSION: u8;
}


/// The standard encoder for Bitcoin networks. Parameterized by a `NetworkParams` type.
pub struct BitcoinEncoder<P: NetworkParams>(PhantomData<P>);

impl<P: NetworkParams> AddressEncoder for BitcoinEncoder<P> {
    type Address = Address;
    type Error = EncodingError;

    fn encode_address(s: Script) -> EncodingResult<Address> {
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

    fn decode_address(addr: Address) -> EncodingResult<Script> {
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

    fn wrap_string(_s: String) -> EncodingResult<Address> {
        unimplemented!()
    }
}

/// A param struct for Bitcoin Mainnet
pub struct Main;

impl NetworkParams for Main {
    const HRP: &'static str = "bc";
    const PKH_VERSION: u8 = 0x00;
    const SH_VERSION: u8 = 0x05;
}

/// A param struct for Bitcoin Tesnet
pub struct Test;

impl NetworkParams for Test {
    const HRP: &'static str = "tb";
    const PKH_VERSION: u8 = 0x6f;
    const SH_VERSION: u8 = 0xc4;
}

/// A param struct for Bitcoin Signet
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
