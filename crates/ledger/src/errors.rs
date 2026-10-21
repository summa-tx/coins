use thiserror::Error;

use crate::common::StatusWord;

/// APDU-related errors
#[derive(Debug, Error)]
pub enum LedgerError {
    /// A command was built without a class byte.
    #[error("APDU command is missing its CLA byte")]
    MissingCla,

    /// A command was built without an instruction byte.
    #[error("APDU command is missing its INS byte")]
    MissingIns,

    /// APDU data exceeds the 255-byte limit of a short APDU.
    #[error("APDU data too long: {0} bytes, max 255")]
    DataTooLong(usize),

    /// APDU Response was too short
    #[error("Response too short. Expected at least 2 bytes. Got {0} bytes.")]
    ResponseTooShort(usize),

    /// The device returned a non-success status word.
    #[error("Ledger device: APDU response error {0}")]
    BadRetcode(StatusWord),

    /// The backend has been disconnected.
    #[error("The backend has been disconnected.")]
    BackendGone,

    /// Native transport error type.
    #[error(transparent)]
    NativeTransportError(#[from] crate::transports::native::NativeTransportError),
}

impl From<StatusWord> for LedgerError {
    fn from(sw: StatusWord) -> Self {
        LedgerError::BadRetcode(sw)
    }
}
