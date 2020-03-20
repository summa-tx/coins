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
use std::marker::PhantomData;

pub trait NetworkParams {
    const HRP: &'static str;
    const PKH_VERSION: u8;
    const SH_VERSION: u8;
}

pub struct Network<P: NetworkParams>(PhantomData<P>);

impl<P: NetworkParams> Network<P> {
    pub fn encode_address(a: Script) -> EncodingResult<Address> {
        match a.determine_type() {
            ScriptType::PKH => {
                Ok(Address::PKH(encode_base58(P::PKH_VERSION, &a.items)))
            },
            ScriptType::SH => {
                Ok(Address::SH(encode_base58(P::SH_VERSION, &a.items)))
            },
            ScriptType::WSH => {
                Ok(Address::WSH(encode_bech32(P::HRP, &a.items)?))
            }
            ScriptType::WPKH => {
                Ok(Address::WPKH(encode_bech32(P::HRP, &a.items)?))
            }
            ScriptType::NonStandard => {
                Err(EncodingError::UnknownScriptType)
            }
        }

        // unimplemented!();
    }

    pub fn decode_address(addr: Address) -> EncodingResult<Script> {
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
}

pub type BitcoinMainnet = Network<Main>;
pub type BitcoinRegtest = Network<Test>;
pub type BitcoinSignet = Network<Signet>;

pub struct Main;

impl NetworkParams for Main {
    const HRP: &'static str = "bc";
    const PKH_VERSION: u8 = 0x00;
    const SH_VERSION: u8 = 0x05;
}

pub struct Test;

impl NetworkParams for Test {
    const HRP: &'static str = "tb";
    const PKH_VERSION: u8 = 0x6f;
    const SH_VERSION: u8 = 0xc4;
}

pub struct Signet;

impl NetworkParams for Signet {
    const HRP: &'static str = "sb";
    const PKH_VERSION: u8 = 0x7d;
    const SH_VERSION: u8 = 0x57;
}
