use js_sys;
use wasm_bindgen::prelude::*;

use bitcoin_spv::types::{Hash256Digest};
use riemann_core::{
    types::primitives::{PrefixVec},
    ser::{Ser}
};
use riemann_bitcoin::{
    hashes::TXID,
    types::{script, txin},
};

use crate::errors::WasmError;


wrap_struct!(txin::BitcoinOutpoint);
wrap_struct!(txin::BitcoinTxIn);
wrap_struct!(txin::Vin);

impl_simple_getter!(BitcoinOutpoint, idx, u32);
impl_simple_getter!(BitcoinTxIn, sequence, u32);
impl_wrapped_getter!(BitcoinTxIn, outpoint, BitcoinOutpoint);

#[wasm_bindgen]
impl BitcoinOutpoint {
    pub fn null() -> Self {
        txin::BitcoinOutpoint::null().into()
    }

    pub fn default() -> Self {
        txin::BitcoinOutpoint::null().into()
    }

    #[wasm_bindgen(constructor)]
    pub fn new(txid: &[u8], idx: u32) -> Self {
        let mut h = Hash256Digest::default();
        h.copy_from_slice(&txid[..32]);
        txin::BitcoinOutpoint::new(TXID::from(h), idx).into()
    }

    #[wasm_bindgen(method, getter)]
    pub fn txid(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.0.txid.0[..])
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

#[wasm_bindgen]
impl Vin {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(txin::Vin::new(vec![]))
    }

    pub fn push(&mut self, input: &BitcoinTxIn) {
         self.0.push(input.0.clone())
    }

    #[wasm_bindgen(method, getter)]
    pub fn items(&self) -> js_sys::Array {
        self.0.items()
            .into_iter()
            .map(|v| BitcoinTxIn::from(v.clone()))
            .map(JsValue::from)
            .collect()
    }
}
