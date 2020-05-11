//! Simple types for Bitcoin Script Witness stack datastructures, each of which are treated as
//! opaque, wrapped `Vec<u8>` instance.
//!
//! We do not handle assembly, disassembly, or Script execution in riemann. Scripts are treated as
//! opaque bytes vectors with no semantics.
//!
//! Scripts can be freely converted between eachother using `From` and `Into`. This merely rewraps
//! the underlying `Vec<u8>` in the new type.
//!
//! For a complete Script builder solution see
//! [rust-bitcoin's](https://github.com/rust-bitcoin/rust-bitcoin) builder.
//!
//! For a macro version for in-line scripts, see mappum's
//! [rust-bitcoin-script](https://github.com/mappum/rust-bitcoin-script). This crate uses the
//! builder under the hood.
//!
//! In order to convert a `bitcoin::Script` to any variation of `riemann::Script`, use
//!
//! ```compile_fail
//! let script = bitcoin::Script::new(/* your script info */);
//! let script = rmn_btc::types::Script::from(script.into_bytes());
//! ```
use riemann_core::types::tx::RecipientIdentifier;

/// A wrapped script.
pub trait BitcoinScript {}

wrap_prefixed_byte_vector!(
    /// A Script is marked Vec<u8> for use as an opaque `Script` in `SighashArgs`
    /// structs.
    ///
    /// `Script::null()` and `Script::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    Script
);
wrap_prefixed_byte_vector!(
    /// A ScriptSig is a marked Vec<u8> for use in the script_sig.
    ///
    /// `ScriptSig::null()` and `ScriptSig::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    ScriptSig
);
wrap_prefixed_byte_vector!(
    /// A WitnessStackItem is a marked `Vec<u8>` intended for use in witnesses. Each
    /// Witness is a `PrefixVec<WitnessStackItem>`. The Transactions `witnesses` is a non-prefixed
    /// `Vec<Witness>.`
    ///
    /// `WitnessStackItem::null()` and `WitnessStackItem::default()` return the empty byte vector
    /// with a 0 prefix, which represents numerical 0, or null bytestring.
    ///
    WitnessStackItem
);
wrap_prefixed_byte_vector!(
    /// A ScriptPubkey is a marked Vec<u8> for use as a `RecipientIdentifier` in
    /// Bitcoin TxOuts.
    ///
    /// `ScriptPubkey::null()` and `ScriptPubkey::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    ScriptPubkey
);

impl BitcoinScript for Script {}

impl BitcoinScript for ScriptPubkey {}

impl BitcoinScript for ScriptSig {}

impl BitcoinScript for WitnessStackItem {}

impl_script_conversion!(Script, ScriptPubkey);
impl_script_conversion!(Script, ScriptSig);
impl_script_conversion!(Script, WitnessStackItem);
impl_script_conversion!(ScriptPubkey, ScriptSig);
impl_script_conversion!(ScriptPubkey, WitnessStackItem);
impl_script_conversion!(ScriptSig, WitnessStackItem);

impl RecipientIdentifier for ScriptPubkey {}

/// A Witness is a `PrefixVec` of `WitnessStackItem`s. This witness corresponds to a single input.
///
/// # Note
///
/// The transaction's witness is composed of many of these `Witness`es in an UNPREFIXED vector.
pub type Witness = Vec<WitnessStackItem>;

/// A TxWitness is the UNPREFIXED vector of witnesses
pub type TxWitness = Vec<Witness>;

/// Standard script types, and a non-standard type for all other scripts.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ScriptType {
    /// Pay to Pubkeyhash.
    PKH,
    /// Pay to Scripthash.
    SH,
    /// Pay to Witness Pubkeyhash.
    WPKH,
    /// Pay to Witness Scripthash.
    WSH,
    /// OP_RETURN
    #[allow(non_camel_case_types)]
    OP_RETURN,
    /// Nonstandard or unknown `Script` type. May be a newer witness version.
    NonStandard,
}

impl ScriptPubkey {
    /// Extract the op return payload. None if not an op return. Does not extract OP_RETURN blobs
    /// larger than 75 bytes.
    pub fn extract_op_return_data(&self) -> Option<Vec<u8>> {
        // check before indexing to avoid potential panic on malformed input
        if self.len() < 2 {
            return None;
        }

        if self[0] == 0x6a && self[1] <= 75 && self[1] as usize == (self.len() - 2) {
            return Some(self.0[2..].to_vec());
        }
        None
    }

    /// Inspect the `Script` to determine its type.
    pub fn standard_type(&self) -> ScriptType {
        if self.extract_op_return_data().is_some() {
            return ScriptType::OP_RETURN;
        }

        let items = &self.0;
        match self.0.len() {
            0x19 => {
                // PKH;
                if items[0..3] == [0x76, 0xa9, 0x14] && items[0x17..] == [0x88, 0xac] {
                    ScriptType::PKH
                } else {
                    ScriptType::NonStandard
                }
            }
            0x17 => {
                // SH
                if items[0..2] == [0xa9, 0x14] && items[0x16..] == [0x87] {
                    ScriptType::SH
                } else {
                    ScriptType::NonStandard
                }
            }
            0x16 => {
                // WPKH
                if items[0..2] == [0x00, 0x14] {
                    ScriptType::WPKH
                } else {
                    ScriptType::NonStandard
                }
            }
            0x22 => {
                if items[0..2] == [0x00, 0x20] {
                    ScriptType::WSH
                } else {
                    ScriptType::NonStandard
                }
            }
            _ => ScriptType::NonStandard,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use riemann_core::ser::ByteFormat;

    #[test]
    fn it_serializes_and_derializes_scripts() {
        let cases = [
            (
                Script::new(hex::decode("0014758ce550380d964051086798d6546bebdca27a73").unwrap()),
                "160014758ce550380d964051086798d6546bebdca27a73",
                22,
            ),
            (Script::new(vec![]), "00", 0),
            (Script::null(), "00", 0),
        ];
        for case in cases.iter() {
            let prevout_script = Script::deserialize_hex(case.1).unwrap();
            assert_eq!(case.0.serialize_hex().unwrap(), case.1);
            assert_eq!(case.0.len(), case.2);
            assert_eq!(case.0.is_empty(), case.2 == 0);

            assert_eq!(prevout_script, case.0);
            assert_eq!(prevout_script.serialize_hex().unwrap(), case.1);
            assert_eq!(prevout_script.len(), case.2);
            assert_eq!(prevout_script.is_empty(), case.2 == 0);
        }
    }

    #[test]
    fn it_serializes_and_derializes_witness_stack_items() {
        let cases = [
            (
                WitnessStackItem::new(
                    hex::decode("0014758ce550380d964051086798d6546bebdca27a73").unwrap(),
                ),
                "160014758ce550380d964051086798d6546bebdca27a73",
                22,
            ),
            (WitnessStackItem::new(vec![]), "00", 0),
            (WitnessStackItem::null(), "00", 0),
        ];
        for case in cases.iter() {
            let prevout_script = WitnessStackItem::deserialize_hex(case.1).unwrap();
            assert_eq!(case.0.serialize_hex().unwrap(), case.1);
            assert_eq!(case.0.len(), case.2);
            assert_eq!(case.0.is_empty(), case.2 == 0);

            assert_eq!(prevout_script, case.0);
            assert_eq!(prevout_script.serialize_hex().unwrap(), case.1);
            assert_eq!(prevout_script.len(), case.2);
            assert_eq!(prevout_script.is_empty(), case.2 == 0);
        }
    }

    #[test]
    fn it_converts_between_bitcoin_script_types() {
        let si = WitnessStackItem::new(
            hex::decode("0014758ce550380d964051086798d6546bebdca27a73").unwrap(),
        );
        let sc = Script::from(si.items());
        let spk = ScriptPubkey::from(si.items());
        let ss = ScriptSig::from(si.items());
        WitnessStackItem::from(si.items());

        WitnessStackItem::from(&sc);
        WitnessStackItem::from(&spk);
        WitnessStackItem::from(&ss);

        Script::from(&si);
        Script::from(&spk);
        Script::from(&ss);

        ScriptPubkey::from(&si);
        ScriptPubkey::from(&sc);
        ScriptPubkey::from(&ss);

        ScriptSig::from(&si);
        ScriptSig::from(&sc);
        ScriptSig::from(&spk);
    }

    #[test]
    fn it_determines_script_pubkey_types_accurately() {
        let cases = [
            (ScriptPubkey::new(hex::decode("a914e88869b88866281ab166541ad8aafba8f8aba47a87").unwrap()), ScriptType::SH),
            (ScriptPubkey::new(hex::decode("a914e88869b88866281ab166541ad8aafba8f8aba47a89").unwrap()), ScriptType::NonStandard), // wrong last byte
            (ScriptPubkey::new(hex::decode("aa14e88869b88866281ab166541ad8aafba8f8aba47a87").unwrap()), ScriptType::NonStandard), // wrong first byte
            (ScriptPubkey::new(hex::decode("76a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488ac").unwrap()), ScriptType::PKH),
            (ScriptPubkey::new(hex::decode("76a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488ad").unwrap()), ScriptType::NonStandard), // wrong last byte
            (ScriptPubkey::new(hex::decode("77a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488ac").unwrap()), ScriptType::NonStandard), // wrong first byte
            (ScriptPubkey::new(hex::decode("00201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc99").unwrap()), ScriptType::WSH),
            (ScriptPubkey::new(hex::decode("01201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc99").unwrap()), ScriptType::NonStandard), // wrong witness program version
            (ScriptPubkey::new(hex::decode("00141bf8a1831db5443b42a44f30a121d1b616d011ab").unwrap()), ScriptType::WPKH),
            (ScriptPubkey::new(hex::decode("01141bf8a1831db5443b42a44f30a121d1b616d011ab").unwrap()), ScriptType::NonStandard), // wrong witness program version
            (ScriptPubkey::new(hex::decode("0011223344").unwrap()), ScriptType::NonStandard), // junk
            (ScriptPubkey::new(hex::decode("deadbeefdeadbeefdeadbeefdeadbeef").unwrap()), ScriptType::NonStandard), // junk
            (ScriptPubkey::new(hex::decode("02031bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc99041bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc9902af").unwrap()), ScriptType::NonStandard), // Raw msig
        ];

        for case in cases.iter() {
            let (script, t) = case;
            assert_eq!(script.standard_type(), *t);
        }
    }
}
