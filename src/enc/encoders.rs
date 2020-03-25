use std::{
    marker::{PhantomData},
};

use crate::{
    enc::bases::{
        Address,
        EncodingError,
        EncodingResult,
        encode_base58,
        decode_base58,
        encode_bech32,
        decode_bech32,
    },
    types::{
        primitives::{PrefixVec},
        script::{Script, ScriptType},
    },
};


pub trait NetworkParams {
    const HRP: &'static str;
    const PKH_VERSION: u8;
    const SH_VERSION: u8;
}

pub trait NetworkEncoder {
    fn encode_address(s: Script) -> EncodingResult<Address>;
    fn decode_address(addr: Address) -> EncodingResult<Script>;
    fn wrap_string(s: String) -> EncodingResult<Address>;
}

pub struct AddressEncoder<P: NetworkParams>(PhantomData<P>);

impl<P: NetworkParams> NetworkEncoder for AddressEncoder<P> {
    fn encode_address(s: Script) -> EncodingResult<Address> {
        match s.determine_type() {
            ScriptType::PKH => {
                Ok(Address::PKH(encode_base58(P::PKH_VERSION, &s.items())))
            },
            ScriptType::SH => {
                Ok(Address::SH(encode_base58(P::SH_VERSION, &s.items())))
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

pub struct Sig;

impl NetworkParams for Sig {
    const HRP: &'static str = "sb";
    const PKH_VERSION: u8 = 0x7d;
    const SH_VERSION: u8 = 0x57;
}

pub type MainnetEncoder = AddressEncoder<Main>;
pub type TestnetEncoder = AddressEncoder<Test>;
pub type SignetEncoder = AddressEncoder<Sig>;
