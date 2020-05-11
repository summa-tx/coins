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

    /// Transport specific error
    #[error("APDU Exchange Error")]
    APDUExchangeError,

    /// Native transport error type.
    #[error(transparent)]
    #[cfg(not(target_arch = "wasm32"))]
    NativeTransportError(#[from] crate::transports::hid::NativeTransportError)
}

impl From<APDUResponseCodes> for LedgerError {
    fn from(r: APDUResponseCodes) -> Self {
        LedgerError::BadRetcode(r)
    }
}
