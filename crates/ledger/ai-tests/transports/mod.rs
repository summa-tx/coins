//! AI-written test doubles for the transport layer. A submodule of
//! `src/transports/mod.rs`. `MockTransport` replaces the HID handle behind
//! `Ledger`.

use std::{collections::VecDeque, error::Error, fmt, time::Duration};

use super::{DeviceIdentity, LedgerTransport};
use crate::{
    Model,
    common::{ApduAnswer, ApduBuffer, ApduCommand, StatusWord},
    errors::LedgerError,
};

/// What the HID transport yields for a response of `data` then `status`.
pub(crate) fn answer(data: &[u8], status: StatusWord) -> Result<ApduAnswer, LedgerError> {
    let mut buf = ApduBuffer::new();
    buf.extend_from_slice(data).expect("mock response fits");
    buf.extend_from_slice(&status.to_be_bytes())
        .expect("mock response fits");
    ApduAnswer::from_answer(buf)?.into_result()
}

/// What `MockTransport` reports once its script runs out. Stands in for a
/// third-party transport's own error type.
#[derive(Debug)]
pub(crate) struct ScriptExhausted;

impl fmt::Display for ScriptExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mock transport has no more replies")
    }
}

impl Error for ScriptExhausted {}

/// A scripted transport: hands out queued replies, records what it saw.
#[derive(Debug, Default)]
pub(crate) struct MockTransport {
    replies: VecDeque<Result<ApduAnswer, LedgerError>>,
    pub(crate) sent: Vec<ApduCommand>,
    pub(crate) timeouts: Vec<Option<Duration>>,
}

impl MockTransport {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Queue a success reply carrying `data`.
    pub(crate) fn reply(self, data: &[u8]) -> Self {
        self.reply_with(data, StatusWord::SUCCESS)
    }

    /// Queue a reply of `data` then `status`.
    pub(crate) fn reply_with(mut self, data: &[u8], status: StatusWord) -> Self {
        self.replies.push_back(answer(data, status));
        self
    }

    /// Queue a transport failure.
    pub(crate) fn fail(mut self, err: LedgerError) -> Self {
        self.replies.push_back(Err(err));
        self
    }
}

impl LedgerTransport for &mut MockTransport {
    fn identity(&self) -> Option<crate::transports::DeviceIdentity<'_>> {
        None
    }

    async fn exchange(
        &mut self,
        packet: ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        self.sent.push(packet);
        self.timeouts.push(timeout);
        self.replies
            .pop_front()
            .unwrap_or(Err(LedgerError::Transport(Box::new(ScriptExhausted))))
    }
}

#[test]
fn device_identity_display_is_model_and_serial() {
    let with_serial = DeviceIdentity::new(Model::NanoX, Some("0001"));
    assert_eq!(with_serial.to_string(), "Nano X (0001)");
    assert_eq!(with_serial.model(), Model::NanoX);
    assert_eq!(with_serial.serial_number(), Some("0001"));

    let without = DeviceIdentity::new(Model::NanoX, None);
    assert_eq!(without.to_string(), "Nano X");
    assert_eq!(without.serial_number(), None);
}
