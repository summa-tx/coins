//! Transaction types.

use wasm_bindgen::prelude::*;

use bitcoins::prelude::*;

use coins_core::{
    ser::ByteFormat,
    types::tx::Transaction,
};

use crate::{
    hashes::{TXID, WTXID},
    types::{
        errors::WasmError,
        script::{TxWitness, Witness},
        txin::{BitcoinTxIn, Vin},
        txout::{TxOut, Vout},
    },
};

wrap_struct!(
    /// A legacy bitcoin transaction object.
    legacy::LegacyTx
);
wrap_struct!(
    /// A witness bitcoin transaction object.
    witness::WitnessTx
);
wrap_struct!(
    /// A bitcoin transaction object.
    tx::BitcoinTx
);

impl_getter_passthrough!(LegacyTx, version, u32);
impl_getter_passthrough!(LegacyTx, locktime, u32);
impl_wrapped_getter_passthrough!(LegacyTx, txid, TXID);

impl_getter_passthrough!(WitnessTx, version, u32);
impl_getter_passthrough!(WitnessTx, locktime, u32);
impl_wrapped_getter_passthrough!(WitnessTx, txid, TXID);
impl_wrapped_getter_passthrough!(WitnessTx, wtxid, WTXID);

impl_getter_passthrough!(BitcoinTx, version, u32);
impl_getter_passthrough!(BitcoinTx, locktime, u32);
impl_wrapped_getter_passthrough!(BitcoinTx, txid, TXID);


#[wasm_bindgen]
impl LegacyTx {
    /// Instantiate a new Legacy Tx.
    #[wasm_bindgen(constructor)]
    pub fn new(version: u32, vin: Vin, vout: Vout, locktime: u32) -> Result<LegacyTx, JsValue> {
        legacy::LegacyTx::new(version, vin.inner(), vout.inner(), locktime)
            .map(Self::from)
            .map_err(crate::types::errors::WasmError::from)
            .map_err(JsValue::from)
    }

    /// Return a clone of the transaction input vector
    #[wasm_bindgen(method, getter)]
    pub fn inputs(&self) -> js_sys::Array {
        self.0
            .inputs()
            .iter()
            .map(Clone::clone)
            .map(BitcoinTxIn::from)
            .map(JsValue::from)
            .collect()
    }

    /// Return a clone of the transaction output vector
    #[wasm_bindgen(method, getter)]
    pub fn outputs(&self) -> js_sys::Array {
        self.0
            .outputs()
            .iter()
            .map(Clone::clone)
            .map(TxOut::from)
            .map(JsValue::from)
            .collect()
    }

    /// Calculate the sighash digest of an input in the vin.
    #[wasm_bindgen]
    pub fn sighash(
        &self,
        index: usize,
        flag: u8,
        prevout_script: &[u8],
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let sighash_flag = Sighash::from_u8(flag)
            .map_err(WasmError::from)
            .map_err(JsValue::from)?;
        let args = legacy::LegacySighashArgs {
            index,
            sighash_flag,
            prevout_script: script::Script::from(prevout_script),
        };
        self.0
            .sighash(&args)
            .map(|v| js_sys::Uint8Array::from(&v.as_ref()[..]))
            .map_err(WasmError::from)
            .map_err(JsValue::from)
    }
}

#[wasm_bindgen]
impl WitnessTx {
    /// Instantiate a new Witness Tx.
    #[wasm_bindgen(constructor)]
    pub fn new(version: u32, vin: Vin, vout: Vout, witnesses: TxWitness, locktime: u32) -> Result<WitnessTx, JsValue> {
        // disambiguate `new`
        <witness::WitnessTx as witness::WitnessTransaction>::new(
            version,
            vin.inner(),
            vout.inner(),
            witnesses,
            locktime,
        )
        .map(Self::from)
        .map_err(crate::types::errors::WasmError::from)
        .map_err(JsValue::from)
    }

    /// Return a clone of the transaction input vector
    #[wasm_bindgen(method, getter)]
    pub fn inputs(&self) -> js_sys::Array {
        self.0
            .inputs()
            .iter()
            .map(Clone::clone)
            .map(BitcoinTxIn::from)
            .map(JsValue::from)
            .collect()
    }

    /// Return a clone of the transaction output vector
    #[wasm_bindgen(method, getter)]
    pub fn outputs(&self) -> js_sys::Array {
        self.0
            .outputs()
            .iter()
            .map(Clone::clone)
            .map(TxOut::from)
            .map(JsValue::from)
            .collect()
    }

    /// Return a clone of the transaction witness vector
    #[wasm_bindgen(method, getter)]
    pub fn witnesses(&self) -> js_sys::Array {
        self.0
            .witnesses()
            .iter()
            .map(Clone::clone)
            .map(Witness::from)
            .map(JsValue::from)
            .collect()
    }

    /// Calculate the sighash digest of an input in the vin.
    #[wasm_bindgen]
    pub fn sighash(
        &self,
        index: usize,
        flag: u8,
        prevout_script: &[u8],
        prevout_value: u64,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let sighash_flag = Sighash::from_u8(flag)
            .map_err(WasmError::from)
            .map_err(JsValue::from)?;
        let args = witness::WitnessSighashArgs {
            index,
            sighash_flag,
            prevout_script: script::Script::from(prevout_script),
            prevout_value,
        };
        self.0
            .sighash(&args)
            .map(|v| js_sys::Uint8Array::from(&v.as_ref()[..]))
            .map_err(WasmError::from)
            .map_err(JsValue::from)
    }
}
