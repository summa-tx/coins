use js_sys;
use wasm_bindgen::prelude::*;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use bitcoin_spv::types::{Hash256Digest};

use riemann_core::{
    hashes::marked::{MarkedDigest},
    ser::{Ser},
};
use riemann_bitcoin::{
    hashes,
};

use crate::errors::WasmError;

wrap_struct!(hashes::TXID);
wrap_struct!(hashes::WTXID);

#[wasm_bindgen]
impl TXID {
    #[wasm_bindgen(constructor)]
    pub fn new(digest: &[u8]) -> Self {
        let mut h = Hash256Digest::default();
        h.copy_from_slice(&digest[..32]);
        hashes::TXID::from(h).into()
    }

    #[wasm_bindgen(method, getter)]
    pub fn internal(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.0.internal()[..])
    }
}

#[wasm_bindgen]
impl WTXID {
    #[wasm_bindgen(constructor)]
    pub fn new(digest: &[u8]) -> Self {
        let mut h = Hash256Digest::default();
        h.copy_from_slice(&digest[..32]);
        hashes::WTXID::from(h).into()
    }

    #[wasm_bindgen(method, getter)]
    pub fn internal(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.0.internal()[..])
    }
}
