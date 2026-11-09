use std::time::Duration;

use thiserror::Error;

use crate::{common::StatusWord, transports::NativeTransportError};

/// Errors from building, exchanging, and parsing APDUs.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// A command was built without a class byte.
    #[error("APDU command is missing its CLA byte. Hint: set it with `CommandBuilder::cla`.")]
    MissingCla,

    /// A command was built without an instruction byte.
    #[error("APDU command is missing its INS byte. Hint: set it with `CommandBuilder::ins`.")]
    MissingIns,

    /// APDU data exceeds the 255-byte limit of a short APDU.
    #[error(
        "APDU data too long: {0} bytes, max 255. Hint: split the data across several commands."
    )]
    DataTooLong(usize),

    /// APDU Response was too short
    #[error(
        "Ledger response too short: {0} bytes, expected at least 2 for the status word. Hint: This may indicate an incompatible device."
    )]
    ResponseTooShort(usize),

    /// The device returned a non-success status word.
    #[error("Ledger device rejected the command with status {0}")]
    BadRetcode(StatusWord),

    /// The device did not answer within the timeout.
    #[error(
        "Ledger device did not respond within {0:?}. Hint: confirm the prompt on the device sooner, or raise the timeout with `Ledger::set_timeout`."
    )]
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
