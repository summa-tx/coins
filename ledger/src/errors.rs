use thiserror::Error;

use crate::common::APDUResponseCodes;


/// APDU-related errors
#[derive(Debug, Error)]
pub enum LedgerError {
    /// APDU Response was too short
    #[error("Response too short. Expected at least 2 bytes. Got {0:?}")]
    ResponseTooShort(Vec<u8>),

    /// APDU error
    #[error("Ledger device: APDU Response error `{0}`")]
    BadRetcode(APDUResponseCodes),

    /// JsValue Error
    #[error("JsValue Error: {0}")]
    #[cfg(target_arch = "wasm32")]
    JsError(String),

    /// Native transport error type.
    #[error(transparent)]
    #[cfg(not(target_arch = "wasm32"))]
    NativeTransportError(#[from] crate::transports::hid::NativeTransportError)
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::prelude::JsValue> for LedgerError {
    fn from(r: wasm_bindgen::prelude::JsValue) -> Self {
        LedgerError::JsError(format!("{:#?}", &r))
    }
}

impl From<APDUResponseCodes> for LedgerError {
    fn from(r: APDUResponseCodes) -> Self {
        LedgerError::BadRetcode(r)
    }
}
