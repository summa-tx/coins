use std::time::Duration;

use thiserror::Error;

use crate::{common::ApduBuffer, errors::LedgerError};

/// Errors from the Speculos transport.
#[derive(Error, Debug)]
pub enum SpeculosError {
    /// The socket failed.
    #[error(
        "Speculos APDU socket I/O failed: {0}. Hint: Is Speculos running, with its APDU port reachable?"
    )]
    Io(#[from] std::io::Error),

    /// Speculos announced a response longer than an [`ApduBuffer`] holds.
    #[error(
        "Speculos response too long: {0} bytes, max {max}. Hint: This may indicate an incompatible Speculos version.",
        max = ApduBuffer::CAPACITY
    )]
    ResponseTooLong(usize),

    /// An earlier exchange timed out or was cancelled and its reply has not been read yet.
    #[error(
        "Speculos reply to an earlier exchange still pending. Hint: resolve the prompt on screen, then call `SpeculosTransport::discard_pending`."
    )]
    PendingReply,

    /// The connection is in an unknown state after an earlier failure. Connect
    /// again.
    #[error("Speculos connection broken. Hint: reconnect with `SpeculosTransport::connect`.")]
    Broken,

    /// Speculos did not reply within the duration.
    #[error(
        "Speculos did not reply within {0:?}. Hint: resolve the prompt on screen sooner, or raise the timeout."
    )]
    NoReply(Duration),

    /// An HTTP request to the control API failed, or returned an error status.
    #[error(
        "Speculos control API request failed: {0}. Hint: Is Speculos running, with its API port reachable?"
    )]
    Http(#[from] reqwest::Error),

    /// A response from the control API was not the expected JSON.
    #[error(
        "Speculos control API returned unexpected JSON: {0}. Hint: This may indicate an incompatible Speculos version."
    )]
    Json(#[from] serde_json::Error),

    /// No screen event contained the text within the duration.
    #[error(
        "No Speculos screen event containing {needle:?} within {timeout:?}. Hint: check the expected text against `SpeculosClient::events`."
    )]
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
