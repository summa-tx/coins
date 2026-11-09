//! Ledger HID report framing.
//!
//! Packets or "reports" are individual device communications. An APDU is sent/
//! received as a series of reports.

use crate::{
    common::{ApduAnswer, ApduBuffer, ApduCommand},
    errors::LedgerError,
    transports::native::error::NativeTransportError,
};

/// The channel every report is sent on.
pub(super) const LEDGER_CHANNEL: u16 = 0x0101;
/// The tag byte of every APDU report.
const LEDGER_TAG: u8 = 0x05;
/// A report as written: a report ID byte, which Windows requires and the
/// other platforms tolerate, then 64 bytes.
const LEDGER_PACKET_WRITE_SIZE: usize = 65;
/// A report as read: 64 bytes.
pub(super) const LEDGER_PACKET_READ_SIZE: usize = 64;
/// The payload a written report carries, after the report ID, channel, tag
/// and sequence index.
const LEDGER_WRITE_PAYLOAD_SIZE: usize = LEDGER_PACKET_WRITE_SIZE - 6;

/// A report as written: a report ID byte, then the channel, tag, sequence
/// index, and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WriteReport(pub(super) [u8; LEDGER_PACKET_WRITE_SIZE]);

/// A report as read, before its framing is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadReport {
    pub(super) bytes: [u8; LEDGER_PACKET_READ_SIZE],
    /// The bytes the device sent. The rest of `bytes` is stale.
    pub(super) len: usize,
}

impl ReadReport {
    /// The bytes the device sent after the 5-byte header, once the channel,
    /// tag and sequence index check out.
    fn body(&self, channel: u16, sequence_idx: u16) -> Result<&[u8], NativeTransportError> {
        let bytes = &self.bytes[..self.len];
        let [c0, c1, tag, s0, s1, body @ ..] = bytes else {
            return Err(NativeTransportError::TruncatedReport(self.len));
        };

        // Another channel means another client is talking to the device.
        let got = u16::from_be_bytes([*c0, *c1]);
        if got != channel {
            return Err(NativeTransportError::UnexpectedChannel {
                got,
                expected: channel,
            });
        }
        if *tag != LEDGER_TAG {
            return Err(NativeTransportError::UnexpectedTag(*tag));
        }

        // A mismatch means someone else read a report.
        let got = u16::from_be_bytes([*s0, *s1]);
        if got != sequence_idx {
            return Err(NativeTransportError::SequenceMismatch {
                got,
                expected: sequence_idx,
            });
        }
        Ok(body)
    }
}

/// How far reading a reply has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Progress {
    /// The sequence index of the next report.
    next_seq: u16,
    /// Payload bytes still to come. Unknown, and 0, until the first report.
    remaining: usize,
}

impl Progress {
    /// No report read yet.
    const START: Self = Self {
        next_seq: 0,
        remaining: 0,
    };

    /// Read reports until the reply is complete, passing each payload chunk
    /// to `sink`. The first report carries the 2-byte response length ahead
    /// of the payload.
    ///
    /// A report that cannot be read fails as [`ReadFailure::Read`], carrying
    /// the progress made so the rest of the reply can be drained.
    fn advance(
        mut self,
        channel: u16,
        mut read: impl FnMut() -> Result<ReadReport, LedgerError>,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), ReadFailure> {
        loop {
            tracing::trace!(sequence_idx = self.next_seq, "Reading report from device");
            let report = read().map_err(|err| ReadFailure::Read { err, owed: self })?;
            let body = report.body(channel, self.next_seq)?;
            let payload = if self.next_seq == 0 {
                let [hi, lo, payload @ ..] = body else {
                    return Err(NativeTransportError::TruncatedReport(report.len).into());
                };
                let expected = u16::from_be_bytes([*hi, *lo]) as usize;
                tracing::trace!(expected, "Received response length from device");
                if expected > ApduBuffer::CAPACITY {
                    return Err(NativeTransportError::ResponseTooLong(expected).into());
                }
                self.remaining = expected;
                payload
            } else if body.is_empty() {
                return Err(NativeTransportError::EmptyReport.into());
            } else {
                body
            };

            let take = payload.len().min(self.remaining);
            sink(&payload[..take]);
            self.remaining -= take;
            self.next_seq += 1;
            if self.remaining == 0 {
                return Ok(());
            }
        }
    }

    /// Read and drop the rest of a reply cut short.
    pub(super) fn drain(
        self,
        channel: u16,
        read: impl FnMut() -> Result<ReadReport, LedgerError>,
    ) -> Result<(), ReadFailure> {
        self.advance(channel, read, |_| {})
    }
}

/// Why reading a reply failed.
#[derive(Debug)]
pub(super) enum ReadFailure {
    /// A report could not be read. `owed` is how far the reply had got.
    Read { err: LedgerError, owed: Progress },
    /// A report broke framing.
    Framing(NativeTransportError),
    /// The reply was read in full, but is not a valid answer.
    Answer(LedgerError),
}

impl From<NativeTransportError> for ReadFailure {
    fn from(err: NativeTransportError) -> Self {
        Self::Framing(err)
    }
}

impl ApduBuffer {
    /// Split these bytes into reports on `channel`. The reports carry the
    /// 2-byte length, then the bytes.
    fn packetize(&self, channel: u16) -> impl Iterator<Item = WriteReport> + use<> {
        let apdu = &**self;
        let mut stream = [0u8; 2 + Self::CAPACITY];
        let len = 2 + apdu.len();
        stream[..2].copy_from_slice(&(apdu.len() as u16).to_be_bytes());
        stream[2..len].copy_from_slice(apdu);

        (0..len.div_ceil(LEDGER_WRITE_PAYLOAD_SIZE)).map(move |i| {
            let start = i * LEDGER_WRITE_PAYLOAD_SIZE;
            let chunk = &stream[start..len.min(start + LEDGER_WRITE_PAYLOAD_SIZE)];
            let mut report = [0; LEDGER_PACKET_WRITE_SIZE];
            report[1..3].copy_from_slice(&channel.to_be_bytes());
            report[3] = LEDGER_TAG;
            report[4..6].copy_from_slice(&(i as u16).to_be_bytes());
            report[6..6 + chunk.len()].copy_from_slice(chunk);
            WriteReport(report)
        })
    }

    /// Reassemble bytes from the reports `read` returns, starting at the
    /// first report of a reply.
    fn depacketize(
        channel: u16,
        read: impl FnMut() -> Result<ReadReport, LedgerError>,
    ) -> Result<Self, ReadFailure> {
        let mut answer = Self::new();
        Progress::START.advance(channel, read, |chunk| {
            answer
                .extend_from_slice(chunk)
                .expect("a reply fits in an ApduBuffer");
        })?;
        Ok(answer)
    }
}

impl ApduCommand {
    /// Split this command into reports on `channel`. See
    /// [`ApduBuffer::packetize`].
    pub(super) fn packetize(&self, channel: u16) -> impl Iterator<Item = WriteReport> + use<> {
        self.as_buffer().packetize(channel)
    }
}

impl ApduAnswer {
    /// Reassemble a reply from the reports `read` returns, starting at its
    /// first report. See [`ApduBuffer::depacketize`].
    pub(super) fn depacketize(
        channel: u16,
        read: impl FnMut() -> Result<ReadReport, LedgerError>,
    ) -> Result<Self, ReadFailure> {
        let answer = ApduBuffer::depacketize(channel, read)?;
        Self::from_answer(answer).map_err(ReadFailure::Answer)
    }
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/native/report.rs"]
mod ai_tests;

/*******************************************************************************
 *   (c) 2018-2022 ZondaX GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
