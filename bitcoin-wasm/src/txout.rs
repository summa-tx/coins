use js_sys;
use wasm_bindgen::prelude::*;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use riemann_core::{
    types::primitives::{PrefixVec},
    ser::{Ser}
};
use rmn_btc::{
    types::{script, txout},
};

use crate::errors::WasmError;

wrap_struct!(txout::TxOut);
wrap_struct!(txout::Vout);

impl_simple_getter!(TxOut, value, u64);
impl_prefix_vec_access!(txout::Vout, txout::TxOut);

#[wasm_bindgen]
impl TxOut {
    /// Instantiate a new TxOut.
    #[wasm_bindgen(constructor)]
    pub fn new(value: u64, script_pubkey: &[u8]) -> Self {
        txout::TxOut{
            value,
            script_pubkey: script_pubkey.into()
        }.into()
    }

    /// Instantiate the null TxOut, which is used in Legacy Sighash.
    pub fn null() -> Self {
        txout::TxOut{
            value: 0xffff_ffff_ffff_ffff,
            script_pubkey: script::ScriptPubkey::null()
        }.into()
    }

    /// Instantiate the null TxOut, which is used in Legacy Sighash.
    pub fn default() -> Self {
        txout::TxOut{
            value: 0xffff_ffff_ffff_ffff,
            script_pubkey: script::ScriptPubkey::null()
        }.into()
    }

    #[wasm_bindgen(method, getter)]
    pub fn script_pubkey(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.0.script_pubkey.items())
    }
}
