//! Ledger HID report framing.
//!
//! Packets or "reports" are individual device communications. An APDU is sent/
//! received as a series of reports.

use std::ops::{Deref, Range};

use crate::{
    common::{ApduBuffer, ApduCommand},
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

/// The payload bytes of one report, after its header and, on the first
/// report, the response length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Payload {
    report: ReadReport,
    range: Range<usize>,
}

impl Deref for Payload {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.report.bytes[self.range.clone()]
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
    pub(super) const START: Self = Self {
        next_seq: 0,
        remaining: 0,
    };

    /// True once the whole reply has been read.
    pub(super) const fn is_done(&self) -> bool {
        self.next_seq > 0 && self.remaining == 0
    }

    /// Check that `report` is the next report of the reply on `channel`, and
    /// return its payload. The first report carries the 2-byte response
    /// length ahead of the payload.
    pub(super) fn accept(
        &mut self,
        channel: u16,
        report: ReadReport,
    ) -> Result<Payload, NativeTransportError> {
        let body = report.body(channel, self.next_seq)?;
        let payload = if self.next_seq == 0 {
            let [hi, lo, payload @ ..] = body else {
                return Err(NativeTransportError::TruncatedReport(report.len));
            };
            let expected = u16::from_be_bytes([*hi, *lo]) as usize;
            tracing::trace!(expected, "Received response length from device");
            if expected > ApduBuffer::CAPACITY {
                return Err(NativeTransportError::ResponseTooLong(expected));
            }
            self.remaining = expected;
            payload
        } else if body.is_empty() {
            return Err(NativeTransportError::EmptyReport);
        } else {
            body
        };

        // The payload is the tail of the bytes read. Past `remaining` is
        // padding.
        let start = report.len - payload.len();
        let take = payload.len().min(self.remaining);
        self.remaining -= take;
        self.next_seq += 1;
        Ok(Payload {
            report,
            range: start..start + take,
        })
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
}

impl ApduCommand {
    /// Split this command into reports on `channel`. See
    /// [`ApduBuffer::packetize`].
    pub(super) fn packetize(&self, channel: u16) -> impl Iterator<Item = WriteReport> + use<> {
        self.as_buffer().packetize(channel)
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
