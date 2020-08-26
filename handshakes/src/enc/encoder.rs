//! Defines parameterized Handshake encoders for Mainnet, Testnet, and Regtest.

use std::marker::PhantomData;

use coins_core::{
    enc::{
        bases::{EncodingError, EncodingResult},
        AddressEncoder,
    },
    ser::ByteFormat,
};

use crate::{
    enc::bases::{decode_bech32, encode_bech32},
    types::{LockingScript, LockingScriptType},
};

/// The available Bitcoin Address types, implemented as a type enum around strings.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub enum Address {
    /// Witness Pay to Pubkeyhash
    WPKH(String),
    /// Witness Pay to Scripthash
    WSH(String),
    /// Provably Unspendable OP_RETURN
    #[allow(non_camel_case_types)]
    OP_RETURN(String),
}

impl AsRef<str> for Address {
    fn as_ref(&self) -> &str {
        match &self {
            Address::WPKH(s) => &s,
            Address::WSH(s) => &s,
            Address::OP_RETURN(s) => &s,
        }
    }
}

impl Address {
    /// Get a clone of the string underlying the address type.
    pub fn as_string(&self) -> String {
        match &self {
            Address::WPKH(s) => s.clone(),
            Address::WSH(s) => s.clone(),
            Address::OP_RETURN(s) => s.clone(),
        }
    }

    /// Convert the address to an `addr()` descriptor
    pub fn to_descriptor(&self) -> String {
        format!("addr({})", self.as_string())
    }
}

/// NetworkParams holds the encoding paramteres for a bitcoin-like network. Currently this is
/// composed of the bech32 human-readable prefix for witness addresses.
pub trait NetworkParams {
    /// The BECH32 HRP. "hs" for mainnet.
    const HRP: &'static str;
}

/// Marker trait to simplify encoder representation elsewhere
pub trait HandshakeEncoderMarker:
    AddressEncoder<Address = Address, Error = EncodingError, RecipientIdentifier = LockingScript>
{
}

/// The standard encoder for Bitcoin networks. Parameterized by a `NetworkParams` type and an
/// `coins_bip32::Encoder`. It exposes
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeEncoder<P: NetworkParams>(PhantomData<fn(P) -> P>);

impl<P: NetworkParams> AddressEncoder for HandshakeEncoder<P> {
    type Address = Address;
    type Error = EncodingError;
    type RecipientIdentifier = LockingScript;

    fn encode_address(s: &LockingScript) -> EncodingResult<Address> {
        let mut data = Vec::with_capacity(s.serialized_length());
        s.write_to(&mut data).unwrap();

        match s.standard_type().unwrap_or(LockingScriptType::NonStandard) {
            LockingScriptType::WSH(_) => Ok(Address::WSH(encode_bech32(P::HRP, &data)?)),
            LockingScriptType::WPKH(_) => Ok(Address::WPKH(encode_bech32(P::HRP, &data)?)),
            LockingScriptType::OP_RETURN(_) => {
                Ok(Address::OP_RETURN(encode_bech32(P::HRP, &data)?))
            }
            LockingScriptType::NonStandard => Err(EncodingError::UnknownScriptType),
        }
    }

    fn decode_address(addr: &Address) -> EncodingResult<LockingScript> {
        match &addr {
            Address::WPKH(s) | Address::WSH(s) | Address::OP_RETURN(s) => {
                decode_bech32(P::HRP, &s).map(|v| v.into())
            }
        }
    }

    fn string_to_address(string: &str) -> EncodingResult<Address> {
        let s = string.to_owned();
        let result = decode_bech32(P::HRP, &s)?;

        let (version_and_len, data) = result.split_at(2);
        let version = version_and_len[0];
        let len = version_and_len[1];

        if version == 31 {
            return Ok(Address::OP_RETURN(s));
        }

        if len as usize != data.len() {
            return Err(EncodingError::InvalidSizeError);
        }

        // Only segwit version 0 is currently defined.
        if version == 0 {
            match len {
                20 => return Ok(Address::WPKH(s)),
                32 => return Ok(Address::WSH(s)),
                _ => return Err(EncodingError::UnknownScriptType),
            }
        }

        Err(EncodingError::UnknownScriptType)
    }
}

impl<P: NetworkParams> HandshakeEncoderMarker for HandshakeEncoder<P> {}

/// A param struct for Handshake Mainnet
#[derive(Debug, Clone)]
pub struct Main;

impl NetworkParams for Main {
    const HRP: &'static str = "hs";
}

/// A param struct for Handshake Testnet
#[derive(Debug, Clone)]
pub struct Test;

impl NetworkParams for Test {
    const HRP: &'static str = "ts";
}

/// A param struct for Handshake Regtest
#[derive(Debug, Clone)]
pub struct Reg;

impl NetworkParams for Reg {
    const HRP: &'static str = "rs";
}

/// An encoder for Handshake Mainnet
pub type MainnetEncoder = HandshakeEncoder<Main>;

/// An encoder for Handshake Testnet
pub type TestnetEncoder = HandshakeEncoder<Test>;

/// An encoder for Handshake Regtest
pub type RegtestEncoder = HandshakeEncoder<Reg>;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_wraps_address_strings() {
        let cases = [
            (
                "hs1qt7s3p8mdmunmq7tz7fjkvcjjvvhfg8c04pp2kh".to_owned(),
                Address::WPKH("hs1qt7s3p8mdmunmq7tz7fjkvcjjvvhfg8c04pp2kh".to_owned()),
            ),
            (
                "hs1quf7hffg2v47umufuyd70hykex59gqx7ax4m8zyw72ycyfjns3dys5yath8".to_owned(),
                Address::WSH(
                    "hs1quf7hffg2v47umufuyd70hykex59gqx7ax4m8zyw72ycyfjns3dys5yath8".to_owned(),
                ),
            ),
        ];
        for case in cases.iter() {
            assert_eq!(MainnetEncoder::string_to_address(&case.0).unwrap(), case.1);
        }

        // TODO(mark): more specific error testing
        let errors = [
            "hello",                        // Err(BechError(InvalidLength))
            "this isn't a real address",    // Err(BechError(MissingSeparator))
            "bc10pu8s7rc0pu8s7rc0putt44am", // Err(WrongHRP{})
            "hs10pu8s7rc0pu8s7rc0putt44am", // Err(BechError(InvalidChecksum)
        ];
        for case in errors.iter() {
            match MainnetEncoder::string_to_address(case) {
                Err(_) => {}
                _ => {
                    assert!(false, "expected err");
                }
            }
        }
    }

    #[test]
    fn it_encodes_addresses() {
        let cases = [
            (
                LockingScript::new(
                    hex::decode("0014847453b9831cdb3a873fb4b4084d94bc86f1c374").unwrap(),
                ).unwrap(),
                Address::WPKH("hs1qs3698wvrrndn4pelkj6qsnv5hjr0rsm5fhvcez".to_owned()),
            ),
            (
                LockingScript::new(
                    hex::decode("0014ed32831a50e012539fe8dfb25b1494c66b1c365e").unwrap(),
                ).unwrap(),
                Address::WPKH("hs1qa5egxxjsuqf988lgm7e9k9y5ce43cdj74n38kc".to_owned()),
            ),
            (
                LockingScript::new(
                    hex::decode("0020630cfd3dac0228390daa7564c02005fbac05e43531e91918ac5b1350fb322db8").unwrap(),
                ).unwrap(),
                Address::WSH("hs1qvvx060dvqg5rjrd2w4jvqgq9lwkqtep4x853jx9vtvf4p7ej9kuqlwkutw".to_owned()),
            ),
            (
                LockingScript::new(
                    hex::decode("002037789b4c88d9941afc9f9e5057b7bfee01ea3b92789484d8d95fabd6d1460721").unwrap(),
                ).unwrap(),
                Address::WSH("hs1qxaufknygmx2p4lylneg90dalacq75wuj0z2gfkxet74ad52xquss6xlsqp".to_owned()),
            ),
            (
                LockingScript::new(
                    hex::decode("1f283692ea54f1a4a1b2d62e7764dad69a2f4d3621e69e89f0ff61ac3e5703a478b42c2ad21618b49541").unwrap(),
                ).unwrap(),
                Address::OP_RETURN("hs1lx6fw54835jsm943wwajd44569axnvg0xn6ylplmp4sl9wqay0z6zc2kjzcvtf92p76v9e0".to_owned()),
            ),
            (
                LockingScript::new(
                    hex::decode("1f2849f6d14cdd3ac95baefa5f3ab65990caaf2b2eca73527f2e7aa788403a6c3d73f5cd0a623b918703").unwrap(),
                ).unwrap(),
                Address::OP_RETURN("hs1lf8mdznxa8ty4hth6tuatvkvse2hjktk2wdf87tn657yyqwnv84eltng2vgaerpcr54ad4t".to_owned()),
            ),
        ];
        for case in cases.iter() {
            assert_eq!(MainnetEncoder::encode_address(&case.0).unwrap(), case.1);
        }
    }

    #[test]
    fn it_encodes_addresses_errors() {
        let errors = [
            LockingScript::new(
                hex::decode("ff14ed32831a50e012539fe8dfb25b1494c66b1c365e").unwrap(),
            )
            .unwrap(), // wrong witness program version
        ];

        for case in errors.iter() {
            match MainnetEncoder::encode_address(&case) {
                Err(EncodingError::UnknownScriptType) => {}
                _ => assert!(false, "expected err UnknownScriptType"),
            }
        }
    }

    #[test]
    fn it_allows_you_to_unwrap_strings_from_addresses() {
        // TODO(mark): this shouldn't accept any valid bech32
        let cases = [
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
