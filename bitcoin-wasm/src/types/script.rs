//! Simple type wrappers for `WitnessStackItem` `Witness` and `TxWitness`.

use js_sys;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use wasm_bindgen::prelude::*;

use riemann_core::{ser::Ser, types::primitives::PrefixVec};
use rmn_btc::types::script;

use crate::errors::WasmError;

wrap_struct!(
    /// An item in an input witness's stack.
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
