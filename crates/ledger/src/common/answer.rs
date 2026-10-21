use crate::errors::LedgerError;

use super::{ApduBuffer, StatusWord};

/// An APDU response: data followed by a status word.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ApduAnswer(ApduBuffer);

impl std::ops::Deref for ApduAnswer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl std::fmt::Display for ApduAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ApduAnswer: {{\n\tStatus: {} \n\tData: {:?}\n}}",
            self.status(),
            self.data()
        )
    }
}

impl ApduAnswer {
    /// Wrap a raw response. Errors if shorter than a status word. This is
    /// how a [`LedgerTransport`](crate::transports::LedgerTransport) builds
    /// its replies.
    pub const fn from_answer(response: ApduBuffer) -> Result<ApduAnswer, LedgerError> {
        if response.len() < 2 {
            Err(LedgerError::ResponseTooShort(response.len()))
        } else {
            Ok(Self(response))
        }
    }

    /// `Ok` if the status word is [`StatusWord::SUCCESS`], else
    /// [`LedgerError::BadRetcode`]. Transports apply this so that a
    /// non-success reply surfaces as an error.
    pub fn into_result(self) -> Result<Self, LedgerError> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(self.status().into())
        }
    }

    /// True if the status word is [`StatusWord::SUCCESS`].
    pub fn is_success(&self) -> bool {
        self.status().is_success()
    }

    /// The status word: the trailing two bytes of the response.
    pub fn status(&self) -> StatusWord {
        let n = self.len();
        StatusWord::from_be_bytes([self[n - 2], self[n - 1]])
    }

    /// The response data: everything before the status word.
    pub fn data(&self) -> &[u8] {
        &self.0[..self.len() - 2]
    }
}

#[cfg(test)]
#[path = "../../ai-tests/common/answer.rs"]
mod ai_tests;
