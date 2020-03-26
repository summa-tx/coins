//! Simple types for `Script` and `WitnessStackItem`, each of which are treated as opaque, wrapped
//! `ConcretePrefixVec<u8>` instances.

use std::ops::{Index, IndexMut};

use crate::{
    ser::{SerResult},
    types::{
        tx::{RecipientIdentifier},
        primitives::{ConcretePrefixVec, PrefixVec},
    },
};


macro_rules! wrap_prefix_vec {
    ($wrapper_name:ident, $item:ty) => {

        #[doc(hidden)]
        #[derive(Clone, Debug, Eq, PartialEq, Default)]
        pub struct $wrapper_name(ConcretePrefixVec<$item>);

        impl PrefixVec for $wrapper_name {
            type Item = $item;

            fn null() -> Self {
                Self(Default::default())
            }

            fn set_items(&mut self, v: Vec<Self::Item>) -> SerResult<()> {
                self.0.set_items(v)
            }

            fn set_prefix_len(&mut self, prefix_len: u8) -> SerResult<()> {
                self.0.set_prefix_len(prefix_len)
            }

            fn push(&mut self, i: Self::Item) {
                self.0.push(i)
            }

            fn len(&self) -> usize {
                self.0.len()
            }

            fn len_prefix(&self) -> u8 {
                self.0.len_prefix()
            }

            fn items(&self) -> &[Self::Item] {
                self.0.items()
            }
        }
        impl<T> From<T> for $wrapper_name
        where
        T: Into<ConcretePrefixVec<u8>>
        {
            fn from(v: T) -> Self {
                Self(v.into())
            }
        }

        impl Index<usize> for $wrapper_name {
            type Output = $item;

            fn index(&self, index: usize) -> &Self::Output {
                &self.0[index]
            }
        }

        impl IndexMut<usize> for $wrapper_name {
            fn index_mut(&mut self, index: usize) -> &mut Self::Output {
                &mut self.0[index]
            }
        }

        impl Extend<u8> for $wrapper_name {
            fn extend<I: IntoIterator<Item=$item>>(&mut self, iter: I) {
                self.0.extend(iter)
            }
        }
    }
}

wrap_prefix_vec!(InternalScript, u8);
wrap_prefix_vec!(WitStackItem, u8);

/// A WitnessStackItem is a marked `ConcretePrefixVec<u8>` intended for use in witnesses. Each
/// Witness is a `PrefixVec<WitnessStackItem>`. The Transactions `witnesses` is a non-prefixed
/// `Vec<Witness>.`
///
/// `WitnessStackItem::null()` and `WitnessStackItem::default()` return the empty byte vector with
/// a 0 prefix, which represents numerical 0, or null bytestring.
///
/// TODO: Witness stack items do not permit non-minimal VarInt prefixes. Return an error if the
/// user tries to pass one in to `set_prefix_len`.
pub type WitnessStackItem = WitStackItem;


/// A Witness is a `PrefixVec` of `WitnessStackItem`s. This witness corresponds to a single input.
///
/// # Note
///
/// The transaction's witness is composed of many of these `Witness`es in an UNPREFIXED vector.
pub type Witness = ConcretePrefixVec<WitnessStackItem>;

/// A Script is a marked ConcretePrefixVec<u8> for use in the script_sig, and script_pubkey
/// fields.
///
/// `Script::null()` and `Script::default()` return the empty byte vector with a 0 prefix, which
/// represents numerical 0, or null bytestring.
pub type Script = InternalScript;

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
    NonStandard
}


impl RecipientIdentifier for Script {}

impl Script {
    /// Inspect the `Script` to determine its type.
    pub fn determine_type(&self) -> ScriptType {
        let items = self.0.items();
        match self.0.len() {
            0x19 => {
                // PKH;
                if items[0..=2] == [0x76, 0xa9, 0x14] && items[17..=18] == [0x88, 0xac] {
                    ScriptType::PKH
                } else {
                    ScriptType::NonStandard
                }
            },
            0x17 => {
                // SH
                if items[0..=2] == [0xa9, 0x14] && items[17..=18] == [0x87] {
                    ScriptType::SH
                } else {
                    ScriptType::NonStandard
                }
            },
            0x16 => {
                // WPKH
                if items[0..=1] == [0x00, 0x14] {
                    ScriptType::WPKH
                } else {
                    ScriptType::NonStandard
                }
            },
            0x22 => {
                if items[0..=1] == [0x00, 0x20] {
                    ScriptType::WSH
                } else {
                    ScriptType::NonStandard
                }
            },
            _ => ScriptType::NonStandard
        }
    }
}

#[cfg(test)]
mod test{
    use super::*;
    use crate::{
        ser::{Ser},
        types::primitives::{PrefixVec}
    };

    #[test]
    fn it_serializes_and_derializes_scripts() {
        let cases = [
        (
            Script::new(hex::decode("0014758ce550380d964051086798d6546bebdca27a73".to_owned()).unwrap()),
            "160014758ce550380d964051086798d6546bebdca27a73",
            22
        ),
        (
            Script::new(vec![]),
            "00",
            0
        ),
        (
            Script::null(),
            "00",
            0
        ),
        (
            Script::new_non_minimal(vec![], 9).unwrap(),
            "ff0000000000000000",
            0
        ),
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
            WitnessStackItem::new(hex::decode("0014758ce550380d964051086798d6546bebdca27a73".to_owned()).unwrap()),
            "160014758ce550380d964051086798d6546bebdca27a73",
            22
        ),
        (
            WitnessStackItem::new(vec![]),
            "00",
            0
        ),
        (
            WitnessStackItem::null(),
            "00",
            0
        ),
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
