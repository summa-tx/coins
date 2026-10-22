use std::time::Duration;

use thiserror::Error;

use crate::{common::ApduBuffer, errors::LedgerError};

/// Errors from the Speculos transport.
#[derive(Error, Debug)]
pub enum SpeculosError {
    /// The socket failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Speculos announced a response longer than an [`ApduBuffer`] holds.
    #[error("Speculos response too long: {0} bytes, max {max}", max = ApduBuffer::CAPACITY)]
    ResponseTooLong(usize),

    /// An earlier exchange timed out and its reply has not been read yet.
    #[error("An earlier exchange is still awaiting its reply")]
    PendingReply,

    /// The connection is in an unknown state after an earlier failure. Connect
    /// again.
    #[error("The Speculos connection is broken and must be reopened")]
    Broken,

    /// Speculos did not reply within the duration.
    #[error("Speculos did not reply within {0:?}")]
    NoReply(Duration),
}

impl From<SpeculosError> for LedgerError {
    fn from(err: SpeculosError) -> Self {
        Self::Transport(Box::new(err))
    }
}
