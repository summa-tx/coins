//! Transaction outputs, their components, and the output vector.

use wasm_bindgen::prelude::*;

use bitcoins::types::{script, txout};
use coins_core::ser::ByteFormat;

wrap_struct!(
    /// An Output. This describes a new UTXO to be created. The value is encoded as an LE u64. The
    /// script pubkey encodes the spending constraints.
    txout::TxOut
);
wrap_struct!(
    /// A transaction's Vector of OUTputs.
    txout::Vout
);

impl_simple_getter!(TxOut, value, u64);
impl_prefix_vec_access!(txout::Vout, txout::TxOut);

#[wasm_bindgen]
impl TxOut {
    /// Instantiate a new TxOut.
    #[wasm_bindgen(constructor)]
    pub fn new(value: u64, script_pubkey: &[u8]) -> Self {
        txout::TxOut {
            value,
            script_pubkey: script_pubkey.into(),
        }
        .into()
    }

    /// Instantiate the null TxOut, which is used in Legacy Sighash.
    pub fn null() -> Self {
        txout::TxOut {
            value: 0xffff_ffff_ffff_ffff,
            script_pubkey: script::ScriptPubkey::null(),
        }
        .into()
    }

    /// Instantiate the null TxOut, which is used in Legacy Sighash.
    pub fn default() -> Self {
        txout::TxOut {
            value: 0xffff_ffff_ffff_ffff,
            script_pubkey: script::ScriptPubkey::null(),
        }
        .into()
    }

    /// Return the script_pubkey as a `Uint8Array`
    #[wasm_bindgen(method, getter)]
    pub fn script_pubkey(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.0.script_pubkey.items())
    }
}
