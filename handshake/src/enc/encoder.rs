//! Defines parameterized Handshake encoders for Mainnet, Testnet, and Regtest.

use std::marker::PhantomData;

use coins_core::{enc::AddressEncoder, ser::ByteFormat};

use crate::{
    enc::bases::{
        decode_bech32, encode_bech32, EncodingError, EncodingResult,
    },
    types::{LockingScript, LockingScriptType}
};

/// The available Bitcoin Address types, implemented as a type enum around strings.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub enum Address {
    /// Witness Pay to Pubkeyhash
    WPKH(String),
    /// Witness Pay to Scripthash
    WSH(String),
    /// Provably Unspendable OP_RETURN
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
        let mut data = vec![];
        (*s).write_to(&mut data);

        match s.standard_type() {
            LockingScriptType::WSH(_) => Ok(Address::WSH(encode_bech32(P::HRP, &data)?)),
            LockingScriptType::WPKH(_) => Ok(Address::WPKH(encode_bech32(P::HRP, &data)?)),
            LockingScriptType::OP_RETURN(_) => Ok(Address::OP_RETURN(encode_bech32(P::HRP, &data)?)),
            LockingScriptType::NonStandard => Err(EncodingError::UnknownScriptType),
        }
    }

    fn decode_address(addr: &Address) -> EncodingResult<LockingScript> {
        match &addr {
            Address::WPKH(s) | Address::WSH(s) | Address::OP_RETURN(s) => decode_bech32(P::HRP, &s).map(|v| v.into()),
        }
    }

    fn string_to_address(string: &str) -> EncodingResult<Address> {
        let s = string.to_owned();
        let result = decode_bech32(P::HRP, &s)?;

        if result[0] == 31 {
            return Ok(Address::OP_RETURN(s))
        }

        // Only segwit version 0 is currently defined.
        if result[0] == 0 {
            match result.len() {
                22 => return Ok(Address::WPKH(s)),
                34 => return Ok(Address::WSH(s)),
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
            "hello", // Err(BechError(InvalidLength))
            "this isn't a real address", // Err(BechError(MissingSeparator))
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

    // TODO(mark): test encoding addresses
    /*
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
    */

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
