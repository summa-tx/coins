use crate::types::primitives::{Script, ScriptType};
use crate::enc::{
    Address,
    EncodingError,
    EncodingResult,
    encode_base58,
    decode_base58,
    encode_bech32,
    decode_bech32
};
// use std::convert::From;

pub trait Network {
    const HRP: &'static str;
    const PKH_VERSION: u8;
    const SH_VERSION: u8;

    fn encode_address(a: Script) -> EncodingResult<Address> {
        match a.determine_type() {
            ScriptType::PKH => {
                Ok(Address::PKH(encode_base58(Self::PKH_VERSION, &a.items)))
            },
            ScriptType::SH => {
                Ok(Address::SH(encode_base58(Self::SH_VERSION, &a.items)))
            },
            ScriptType::WSH => {
                Ok(Address::WSH(encode_bech32(Self::HRP, &a.items)?))
            }
            ScriptType::WPKH => {
                Ok(Address::WPKH(encode_bech32(Self::HRP, &a.items)?))
            }
            ScriptType::NonStandard => {
                Err(EncodingError::UnknownScriptType)
            }
        }

        // unimplemented!();
    }

    fn decode_address(addr: Address) -> EncodingResult<Script> {
        match &addr {
            Address::PKH(s) => {
                decode_base58(Self::PKH_VERSION, s).map(|v| v.into())
            },
            Address::SH(s) => {
                decode_base58(Self::SH_VERSION, s).map(|v| v.into())
            },
            Address::WPKH(s) | Address::WSH(s) => {
                decode_bech32(Self::HRP, &s).map(|v| v.into())
            }
        }
    }
}

pub enum Main {}

impl Network for Main {
    const HRP: &'static str = "bc";
    const PKH_VERSION: u8 = 0x00;
    const SH_VERSION: u8 = 0x05;
}

pub enum Test {}

impl Network for Test {
    const HRP: &'static str = "tb";
    const PKH_VERSION: u8 = 0x6f;
    const SH_VERSION: u8 = 0xc4;
}

pub enum Signet {}

impl Network for Signet {
    const HRP: &'static str = "sb";
    const PKH_VERSION: u8 = 0x7d;
    const SH_VERSION: u8 = 0x57;
}
