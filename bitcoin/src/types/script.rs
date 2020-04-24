//! Simple types for Bitcoin Script Witness stack datastructures, each of which are treated as
//! opaque, wrapped `ConcretePrefixVec<u8>` instance.
//!
//! We do not handle assembly, disassembly, or Script execution in riemann. Scripts are treated as
//! opaque bytes vectors with no semantics.
//!
//! Scripts can be freely converted between eachother using `From` and `Into`. This merely rewraps
//! the underlying `ConcretePrefixVec<u8>` in the new type.
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
use riemann_core::types::{
    primitives::{ConcretePrefixVec, PrefixVec},
    tx::RecipientIdentifier,
};

/// A wrapped script.
pub trait BitcoinScript {
    /// Instantiate a new wrapped script
    fn from_script(v: ConcretePrefixVec<u8>) -> Self;
}

wrap_prefixed_byte_vector!(
    /// A Script is marked ConcretePrefixVec<u8> for use as an opaque `Script` in `SighashArgs`
    /// structs.
    ///
    /// `Script::null()` and `Script::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    Script
);
wrap_prefixed_byte_vector!(
    /// A ScriptSig is a marked ConcretePrefixVec<u8> for use in the script_sig.
    ///
    /// `ScriptSig::null()` and `ScriptSig::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    ScriptSig
);
wrap_prefixed_byte_vector!(
    /// A WitnessStackItem is a marked `ConcretePrefixVec<u8>` intended for use in witnesses. Each
    /// Witness is a `PrefixVec<WitnessStackItem>`. The Transactions `witnesses` is a non-prefixed
    /// `Vec<Witness>.`
    ///
    /// `WitnessStackItem::null()` and `WitnessStackItem::default()` return the empty byte vector
    /// with a 0 prefix, which represents numerical 0, or null bytestring.
    ///
    WitnessStackItem
);
wrap_prefixed_byte_vector!(
    /// A ScriptPubkey is a marked ConcretePrefixVec<u8> for use as a `RecipientIdentifier` in
    /// Bitcoin TxOuts.
    ///
    /// `ScriptPubkey::null()` and `ScriptPubkey::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    ScriptPubkey
);

impl BitcoinScript for Script {
    fn from_script(s: ConcretePrefixVec<u8>) -> Self {
        Self(s)
    }
}

impl BitcoinScript for ScriptPubkey {
    fn from_script(s: ConcretePrefixVec<u8>) -> Self {
        Self(s)
    }
}

impl BitcoinScript for ScriptSig {
    fn from_script(s: ConcretePrefixVec<u8>) -> Self {
        Self(s)
    }
}

impl BitcoinScript for WitnessStackItem {
    fn from_script(s: ConcretePrefixVec<u8>) -> Self {
        Self(s)
    }
}

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
pub type Witness = ConcretePrefixVec<WitnessStackItem>;

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
    /// Nonstandard or unknown `Script` type. May be a newer witness version.
    NonStandard,
}

impl ScriptPubkey {
    /// Inspect the `Script` to determine its type.
    pub fn standard_type(&self) -> ScriptType {
        let items = self.0.items();
        match self.0.len() {
            0x19 => {
                // PKH;
                if items[0..=2] == [0x76, 0xa9, 0x14] && items[0x17..] == [0x88, 0xac] {
                    ScriptType::PKH
                } else {
                    ScriptType::NonStandard
                }
            }
            0x17 => {
                // SH
                if items[0..=2] == [0xa9, 0x14] && items[0x15..] == [0x87] {
                    ScriptType::SH
                } else {
                    ScriptType::NonStandard
                }
            }
            0x16 => {
                // WPKH
                if items[0..=1] == [0x00, 0x14] {
                    ScriptType::WPKH
                } else {
                    ScriptType::NonStandard
                }
            }
            0x22 => {
                if items[0..=1] == [0x00, 0x20] {
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
    use riemann_core::{ser::Ser, types::primitives::PrefixVec};

    #[test]
    fn it_serializes_and_derializes_scripts() {
        let cases = [
            (
                Script::new(
                    hex::decode("0014758ce550380d964051086798d6546bebdca27a73".to_owned()).unwrap(),
                ),
                "160014758ce550380d964051086798d6546bebdca27a73",
                22,
            ),
            (Script::new(vec![]), "00", 0),
            (Script::null(), "00", 0),
        ];
        for case in cases.iter() {
            let prevout_script = Script::deserialize_hex(case.1.to_owned()).unwrap();
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
                    hex::decode("0014758ce550380d964051086798d6546bebdca27a73".to_owned()).unwrap(),
                ),
                "160014758ce550380d964051086798d6546bebdca27a73",
                22,
            ),
            (WitnessStackItem::new(vec![]), "00", 0),
            (WitnessStackItem::null(), "00", 0),
        ];
        for case in cases.iter() {
            let prevout_script = WitnessStackItem::deserialize_hex(case.1.to_owned()).unwrap();
            assert_eq!(case.0.serialize_hex().unwrap(), case.1);
            assert_eq!(case.0.len(), case.2);
            assert_eq!(case.0.is_empty(), case.2 == 0);

            assert_eq!(prevout_script, case.0);
            assert_eq!(prevout_script.serialize_hex().unwrap(), case.1);
            assert_eq!(prevout_script.len(), case.2);
            assert_eq!(prevout_script.is_empty(), case.2 == 0);
        }
    }
}
