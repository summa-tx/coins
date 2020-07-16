//! Simple type wrappers for `WitnessStackItem` `Witness` and `TxWitness`.

use wasm_bindgen::prelude::*;

use coins_core::ser::ByteFormat;
use bitcoins::types::script;

wrap_struct!(
    /// A Script is marked Vec<u8> for use as an opaque `Script` in `SighashArgs`
    /// structs.
    ///
    /// `Script::null()` and `Script::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    script::Script
);
wrap_struct!(
    /// A ScriptSig is a marked Vec<u8> for use in the script_sig.
    ///
    /// `ScriptSig::null()` and `ScriptSig::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    script::ScriptSig
);
wrap_struct!(
    /// A ScriptPubkey is a marked Vec<u8> for use as a `RecipientIdentifier` in
    /// Bitcoin TxOuts.
    ///
    /// `ScriptPubkey::null()` and `ScriptPubkey::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    script::ScriptPubkey
);
wrap_struct!(
    /// A WitnessStackItem is a marked `Vec<u8>` intended for use in witnesses. Each
    /// Witness is a `PrefixVec<WitnessStackItem>`. The Transactions `witnesses` is a non-prefixed
    /// `Vec<Witness>.`
    ///
    /// `WitnessStackItem::null()` and `WitnessStackItem::default()` return the empty byte vector
    /// with a 0 prefix, which represents numerical 0, or null bytestring.
    script::WitnessStackItem
);
wrap_struct!(
    /// A witness associated with a single input. Composed of a prefixed vector of
    /// `WitnessStackItem`s.
    script::Witness
);
wrap_struct!(
    /// A witness associated with an entire transaction. Composed of an unprefixed vector
    /// of `Witness`es.
    script::TxWitness
);

impl_prefix_vec_access!(script::Witness, script::WitnessStackItem);
