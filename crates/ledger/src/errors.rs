use std::time::Duration;

use thiserror::Error;

use crate::{common::StatusWord, transports::native::NativeTransportError};

/// Errors from building, exchanging, and parsing APDUs.
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

    /// The device did not answer within the timeout.
    #[error("Ledger device did not respond within {0:?}")]
    Timeout(Duration),

    /// The transport failed. [`NativeTransportError`] for the HID transport;
    /// other transports box their own error type.
    #[error(transparent)]
    Transport(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<NativeTransportError> for LedgerError {
    fn from(err: NativeTransportError) -> Self {
        Self::Transport(Box::new(err))
    }
}

impl From<StatusWord> for LedgerError {
    fn from(sw: StatusWord) -> Self {
        LedgerError::BadRetcode(sw)
    }
}

#[cfg(test)]
#[path = "../ai-tests/errors.rs"]
mod ai_tests;
