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

    /// An HTTP request to the control API failed, or returned an error status.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// A response from the control API was not the expected JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// No screen event contained the text within the duration.
    #[error("No screen event containing {needle:?} within {timeout:?}")]
    TextNotFound {
        /// The text that was awaited.
        needle: String,
        /// How long it was awaited.
        timeout: Duration,
    },
}

impl From<SpeculosError> for LedgerError {
    fn from(err: SpeculosError) -> Self {
        Self::Transport(Box::new(err))
    }
}
