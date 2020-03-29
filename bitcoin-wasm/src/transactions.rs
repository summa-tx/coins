use js_sys;
use wasm_bindgen::prelude::*;

use riemann_bitcoin::{
    script,
    transactions::{self, WitnessTransaction}
};

use riemann_core::{
    types::{
        primitives::{PrefixVec},
        tx::{Transaction},
    },
    ser::{Ser},
};

use crate::{
    errors::{WasmError},
    hashes::{TXID, WTXID},
    txin::{Vin, BitcoinTxIn},
    txout::{Vout, TxOut},
    script::{TxWitness, Witness},
};

wrap_struct!(transactions::LegacyTx);
wrap_struct!(transactions::WitnessTx);

impl_getter_passthrough!(LegacyTx, version, u32);
impl_getter_passthrough!(LegacyTx, locktime, u32);
impl_wrapped_getter_passthrough!(LegacyTx, txid, TXID);

impl_getter_passthrough!(WitnessTx, version, u32);
impl_getter_passthrough!(WitnessTx, locktime, u32);
impl_wrapped_getter_passthrough!(WitnessTx, txid, TXID);
impl_wrapped_getter_passthrough!(WitnessTx, wtxid, WTXID);

#[wasm_bindgen]
impl LegacyTx {
    #[wasm_bindgen(constructor)]
    pub fn new(version: u32, vin: Vin, vout: Vout, locktime: u32) -> Self {
        transactions::LegacyTx::new(
            version,
            vin.inner().items(),
            vout.inner().items(),
            locktime
        ).into()
    }

    #[wasm_bindgen]
    pub fn inputs(&self) -> js_sys::Array {
        self.0.inputs()
            .iter()
            .map(|v| BitcoinTxIn::from(v.clone()))
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen]
    pub fn outputs(&self) -> js_sys::Array {
        self.0.outputs()
            .iter()
            .map(|v| TxOut::from(v.clone()))
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen]
    pub fn sighash(
        &self,
        index: usize,
        flag: u8,
        prevout_script: &[u8]
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let sighash_flag = transactions::sighash_from_u8(flag)
            .map_err(WasmError::from)
            .map_err(JsValue::from)?;
        let args = transactions::LegacySighashArgs{
            index,
            sighash_flag,
            prevout_script: &script::Script::from(prevout_script)
        };
        self.0.sighash(&args)
            .map(|v| js_sys::Uint8Array::from(&v[..]))
            .map_err(WasmError::from)
            .map_err(JsValue::from)
    }
}

#[wasm_bindgen]
impl WitnessTx {
    #[wasm_bindgen(constructor)]
    pub fn new(
        version: u32,
        vin: Vin,
        vout: Vout,
        witnesses: TxWitness,
        locktime: u32
    ) -> Self {
        // disambiguate `new`
        <transactions::WitnessTx as transactions::WitnessTransaction>::new(
            version,
            vin.inner().items(),
            vout.inner().items(),
            witnesses,
            locktime
        ).into()
    }

    #[wasm_bindgen]
    pub fn inputs(&self) -> js_sys::Array {
        self.0.inputs()
            .iter()
            .map(|v| BitcoinTxIn::from(v.clone()))
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen]
    pub fn outputs(&self) -> js_sys::Array {
        self.0.outputs()
            .iter()
            .map(|v| TxOut::from(v.clone()))
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen]
    pub fn witnesses(&self) -> js_sys::Array {
        self.0.witnesses()
            .iter()
            .map(|v| Witness::from(v.clone()))
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen]
    pub fn sighash(
        &self,
        index: usize,
        flag: u8,
        prevout_script: &[u8],
        prevout_value: u64
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let sighash_flag = transactions::sighash_from_u8(flag)
            .map_err(WasmError::from)
            .map_err(JsValue::from)?;
        let args = transactions::WitnessSighashArgs{
            index,
            sighash_flag,
            prevout_script: &script::Script::from(prevout_script),
            prevout_value
        };
        self.0.sighash(&args)
            .map(|v| js_sys::Uint8Array::from(&v[..]))
            .map_err(WasmError::from)
            .map_err(JsValue::from)
    }
}
