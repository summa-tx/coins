//! This module holds `MarkedDigest` types used by Bitcoin transactions. Currently we represent
//! only `TXID`s and `WTXID`s. In the future we may also represent sighash digests this way.

use wasm_bindgen::prelude::*;

use bitcoins::hashes;
use coins_core::{hashes::MarkedDigestOutput, ser::ByteFormat};

wrap_struct!(
    /// A marked Hash256Digest representing transaction IDs
    hashes::TXID
);
wrap_struct!(
    /// A marked Hash256Digest representing witness transaction IDs
    hashes::WTXID
);

#[wasm_bindgen]
impl TXID {
    /// Instantiate a new TXID from a Uint8Array
    #[wasm_bindgen(constructor)]
    pub fn new(digest: &[u8]) -> Self {
        let mut h = hashes::TXID::default();
        h.as_mut_slice().copy_from_slice(&digest[..32]);
        h.into()
    }

    /// Return the underlying digest as a Uint8Array
    #[wasm_bindgen(method, getter)]
    pub fn internal(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.0.as_slice())
    }
}

#[wasm_bindgen]
impl WTXID {
    /// Instantiate a new WTXID from a Uint8Array
    #[wasm_bindgen(constructor)]
    pub fn new(digest: &[u8]) -> Self {
        let mut h = hashes::WTXID::default();
        h.as_mut_slice().copy_from_slice(&digest[..32]);
        h.into()
    }

    /// Return the underlying digest as a Uint8Array
    #[wasm_bindgen(method, getter)]
    pub fn internal(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.0.as_slice())
    }
}
