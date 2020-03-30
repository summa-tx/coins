use wasm_bindgen::prelude::*;

use riemann_core::ser::{SerError};
use rmn_btc::{
    bases::{EncodingError},
    transactions::{TxError},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WasmError {
    #[error("Unknown error in wasm")]
    UnknownError,
    #[error("SerError: {}", .0)]
    SerError(#[from] SerError),
    #[error("TxError: {}", .0)]
    TxError(#[from] TxError),
    #[error("EncodingError: {}", .0)]
    EncodingError(#[from] EncodingError),
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> JsValue {
        JsValue::from_str(&format!("Error: {}", e))
    }
}
