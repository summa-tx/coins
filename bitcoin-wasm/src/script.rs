use js_sys;
use wasm_bindgen::prelude::*;

use riemann_core::{
    types::primitives::{PrefixVec},
    ser::{Ser}
};
use riemann_bitcoin::{
    types::{script},
};

use crate::errors::WasmError;

wrap_struct!(script::WitnessStackItem);
wrap_struct!(script::Witness);
wrap_struct!(script::TxWitness);

impl_prefix_vec_access!(script::Witness, script::WitnessStackItem);
