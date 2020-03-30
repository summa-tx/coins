use js_sys;
use wasm_bindgen::prelude::*;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use riemann_core::{
    types::primitives::{PrefixVec},
    ser::{Ser}
};
use riemann_bitcoin::{
    types::{script, txin},
};

use crate::{
    errors::{WasmError},
    hashes::{TXID},
};


wrap_struct!(txin::BitcoinOutpoint);
wrap_struct!(txin::BitcoinTxIn);
wrap_struct!(txin::Vin);

impl_simple_getter!(BitcoinOutpoint, idx, u32);
impl_wrapped_getter!(BitcoinOutpoint, txid, TXID);

impl_simple_getter!(BitcoinTxIn, sequence, u32);
impl_wrapped_getter!(BitcoinTxIn, outpoint, BitcoinOutpoint);

impl_prefix_vec_access!(txin::Vin, txin::BitcoinTxIn);

#[wasm_bindgen]
impl BitcoinOutpoint {
    pub fn null() -> Self {
        txin::BitcoinOutpoint::null().into()
    }

    pub fn default() -> Self {
        txin::BitcoinOutpoint::null().into()
    }

    #[wasm_bindgen(constructor)]
    pub fn new(txid: &TXID, idx: u32) -> Self {
        txin::BitcoinOutpoint::new(txid.clone().into(), idx).into()
    }
}

#[wasm_bindgen]
impl BitcoinTxIn {
    #[wasm_bindgen(constructor)]
    pub fn new(outpoint: BitcoinOutpoint, script_sig: &[u8], sequence: u32) -> Self {
        txin::BitcoinTxIn::new(
            outpoint.0,
            script::ScriptSig::from(script_sig),
            sequence
        ).into()
    }

    #[wasm_bindgen(method, getter)]
    pub fn script_sig(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.0.script_sig.items())
    }
}
