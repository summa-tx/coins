//! Defines parameterized Bitcoin encoders for Mainnet, Testnet, and Signet.

use std::marker::PhantomData;

use riemann_core::enc::AddressEncoder;

use crate::{
    enc::bases::{
        decode_base58, decode_bech32, encode_base58, encode_bech32, EncodingError, EncodingResult,
    },
    types::script::{ScriptPubkey, ScriptType},
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

/// Marker trait to simplify encoder representation elsewhere
pub trait BitcoinEndcoderMarker: AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = ScriptPubkey>
{}

/// The standard encoder for Bitcoin networks. Parameterized by a `NetworkParams` type and an
/// `rmn_bip32::Encoder`. It exposes
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinEncoder<P: NetworkParams>(PhantomData<*const P>);

impl<P: NetworkParams> AddressEncoder for BitcoinEncoder<P> {
    type Address = Address;
    type Error = EncodingError;
    type RecipientIdentifier = ScriptPubkey;

    fn encode_address(s: &ScriptPubkey) -> EncodingResult<Address> {
        match s.standard_type() {
            ScriptType::PKH => {
                // s.items contains the op codes. we want only the pkh
                Ok(Address::PKH(encode_base58(
                    P::PKH_VERSION,
                    &s.items()[3..23],
                )))
            }
            ScriptType::SH => {
                // s.items contains the op codes. we want only the sh
                Ok(Address::SH(encode_base58(P::SH_VERSION, &s.items()[2..22])))
            }
            ScriptType::WSH => Ok(Address::WSH(encode_bech32(P::HRP, &s.items())?)),
            ScriptType::WPKH => Ok(Address::WPKH(encode_bech32(P::HRP, &s.items())?)),
            ScriptType::OP_RETURN => Err(EncodingError::NullDataScript),
            ScriptType::NonStandard => Err(EncodingError::UnknownScriptType),
        }
    }

    fn decode_address(addr: &Address) -> EncodingResult<ScriptPubkey> {
        match &addr {
            Address::PKH(s) => decode_base58(P::PKH_VERSION, s).map(|v| v.into()),
            Address::SH(s) => decode_base58(P::SH_VERSION, s).map(|v| v.into()),
            Address::WPKH(s) | Address::WSH(s) => decode_bech32(P::HRP, &s).map(|v| v.into()),
        }
    }

    fn string_to_address(string: &str) -> EncodingResult<Address> {
        let s = string.to_owned();
        if s.starts_with(P::HRP) {
            let result = decode_bech32(P::HRP, &s)?;
            match result.len() {
                22 => Ok(Address::WPKH(s)),
                34 => Ok(Address::WSH(s)),
                _ => Err(EncodingError::UnknownScriptType),
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

impl<P: NetworkParams> BitcoinEndcoderMarker for BitcoinEncoder<P> {}

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
            (
                "bc1qza7dfgl2q83cf68fqkkdd754qx546h4u9vd9tg".to_owned(),
                Address::WPKH("bc1qza7dfgl2q83cf68fqkkdd754qx546h4u9vd9tg".to_owned()),
            ),
            (
                "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej".to_owned(),
                Address::WSH(
                    "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej".to_owned(),
                ),
            ),
            (
                "1AqE7oGF1EUoJviX1uuYrwpRBdEBTuGhES".to_owned(),
                Address::PKH("1AqE7oGF1EUoJviX1uuYrwpRBdEBTuGhES".to_owned()),
            ),
            (
                "3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2".to_owned(),
                Address::SH("3HXNFmJpxjgTVFN35Y9f6Waje5YFsLEQZ2".to_owned()),
            ),
        ];
        for case in cases.iter() {
            assert_eq!(MainnetEncoder::string_to_address(&case.0).unwrap(), case.1);
        }

        let errors = [
            "hello",
            "this isn't a real address",
            "bc10pu8s7rc0pu8s7rc0putt44am", // valid bech32, bad length
        ];
        for case in errors.iter() {
            match MainnetEncoder::string_to_address(case) {
                Err(EncodingError::UnknownScriptType) => {}
                _ => assert!(false, "expected err UnknownScriptType"),
            }
        }
    }

    #[test]
    fn it_encodes_addresses() {
        let cases = [
            (
                ScriptPubkey::new(
                    hex::decode("a914e88869b88866281ab166541ad8aafba8f8aba47a87").unwrap(),
                ),
                Address::SH("3NtY7BrF3xrcb31JXXaYCKVcz1cH3Azo5y".to_owned()),
            ),
            (
                ScriptPubkey::new(
                    hex::decode("76a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488ac").unwrap(),
                ),
                Address::PKH("12JvxPk4mT4PKMVHuHc1aQGBZpotQWQwF6".to_owned()),
            ),
            (
                ScriptPubkey::new(
                    hex::decode(
                        "00201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc99",
                    )
                    .unwrap(),
                ),
                Address::WSH(
                    "bc1qr0u2rqcak4zrks4yfuc2zgw3kctdqydtzh0k9dvgwg4ggkryejvsy49jvz".to_owned(),
                ),
            ),
            (
                ScriptPubkey::new(
                    hex::decode("00141bf8a1831db5443b42a44f30a121d1b616d011ab").unwrap(),
                ),
                Address::WPKH("bc1qr0u2rqcak4zrks4yfuc2zgw3kctdqydt3wy5yh".to_owned()),
            ),
        ];
        for case in cases.iter() {
            assert_eq!(MainnetEncoder::encode_address(&case.0).unwrap(), case.1);
        }
        let errors = [
            (ScriptPubkey::new(hex::decode("01201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc99").unwrap())), // wrong witness program version
            (ScriptPubkey::new(hex::decode("a914e88869b88866281ab166541ad8aafba8f8aba47a89").unwrap())), // wrong last byte
            (ScriptPubkey::new(hex::decode("aa14e88869b88866281ab166541ad8aafba8f8aba47a87").unwrap())), // wrong first byte
            (ScriptPubkey::new(hex::decode("76a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488ad").unwrap())), // wrong last byte
            (ScriptPubkey::new(hex::decode("77a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488ac").unwrap())), // wrong first byte
            (ScriptPubkey::new(hex::decode("01141bf8a1831db5443b42a44f30a121d1b616d011ab").unwrap())), // wrong witness program version
            (ScriptPubkey::new(hex::decode("0011223344").unwrap())), // junk
            (ScriptPubkey::new(hex::decode("deadbeefdeadbeefdeadbeefdeadbeef").unwrap())), // junk
            (ScriptPubkey::new(hex::decode("02031bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc99041bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc9902af").unwrap())), // Raw msig
        ];
        for case in errors.iter() {
            match MainnetEncoder::encode_address(case) {
                Err(EncodingError::UnknownScriptType) => {}
                _ => assert!(false, "expected err UnknownScriptType"),
            }
        }
    }

    #[test]
    fn it_allows_you_to_unwrap_strings_from_addresses() {
        let cases = [
            (
                "3NtY7BrF3xrcb31JXXaYCKVcz1cH3Azo5y".to_owned(),
                Address::SH("3NtY7BrF3xrcb31JXXaYCKVcz1cH3Azo5y".to_owned()),
            ),
            (
                "12JvxPk4mT4PKMVHuHc1aQGBZpotQWQwF6".to_owned(),
                Address::PKH("12JvxPk4mT4PKMVHuHc1aQGBZpotQWQwF6".to_owned()),
            ),
            (
                "bc1qr0u2rqcak4zrks4yfuc2zgw3kctdqydtzh0k9dvgwg4ggkryejvsy49jvz".to_owned(),
                Address::WSH(
                    "bc1qr0u2rqcak4zrks4yfuc2zgw3kctdqydtzh0k9dvgwg4ggkryejvsy49jvz".to_owned(),
                ),
            ),
            (
                "bc1qr0u2rqcak4zrks4yfuc2zgw3kctdqydt3wy5yh".to_owned(),
                Address::WPKH("bc1qr0u2rqcak4zrks4yfuc2zgw3kctdqydt3wy5yh".to_owned()),
            ),
        ];
        for case in cases.iter() {
            assert_eq!(case.1.as_string(), case.0);
        }
    }
}
