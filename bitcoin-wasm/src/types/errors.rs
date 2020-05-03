//! Error types used in the library.

use wasm_bindgen::prelude::*;

use riemann_core::ser::SerError;
use rmn_btc::{enc::bases::EncodingError, types::transactions::TxError};

use thiserror::Error;

/// An error type that wraps internal error types into something that can easily
/// be propagated to JS.
#[derive(Debug, Error)]
pub enum WasmError {
    /// An unknown error.
    #[error("Unknown error in wasm")]
    UnknownError,

    /// An error related to serailization.
    #[error(transparent)]
    SerError(#[from] SerError),

    /// An error related to TX operations. Usually itself a wrapped `SerError`
    #[error(transparent)]
    TxError(#[from] TxError),

    /// An error related to Address encoding/decoding. Often a wrapped error from
    /// base58check or bech32 crates. Sometimes a version or HRP mismatch.
    #[error(transparent)]
    EncodingError(#[from] EncodingError),
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> JsValue {
        JsValue::from_str(&format!("Error: {}", e))
    }
}
