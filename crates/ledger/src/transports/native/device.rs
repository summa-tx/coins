//! A Ledger's APDU interface over native HID.
//!
//! Packets or "reports" are individual device communications. An APDU is sent/
//! received as a series of reports.

use std::time::Duration;

#[cfg(target_os = "android")]
use hidapi::HidApi;
use hidapi::HidDevice;
use tracing::{Span, field::display, instrument};

use super::hid::{HidDeviceId, HidJob, HidThread};
use crate::{
    common::{ApduAnswer, ApduBuffer, ApduCommand},
    errors::LedgerError,
    transports::native::error::NativeTransportError,
};

/// The channel every report is sent on.
const LEDGER_CHANNEL: u16 = 0x0101;
/// The tag byte of every APDU report.
const LEDGER_TAG: u8 = 0x05;
/// A report as written: a report ID byte, which Windows requires and the
/// other platforms tolerate, then 64 bytes.
const LEDGER_PACKET_WRITE_SIZE: usize = 65;
/// A report as read: 64 bytes.
const LEDGER_PACKET_READ_SIZE: usize = 64;
/// The payload a written report carries, after the report ID, channel, tag
/// and sequence index.
const LEDGER_WRITE_PAYLOAD_SIZE: usize = LEDGER_PACKET_WRITE_SIZE - 6;

/// A report as written: a report ID byte, then the channel, tag, sequence
/// index, and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteReport([u8; LEDGER_PACKET_WRITE_SIZE]);

/// A report as read, before its framing is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadReport {
    bytes: [u8; LEDGER_PACKET_READ_SIZE],
    /// The bytes the device sent. The rest of `bytes` is stale.
    len: usize,
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
struct Progress {
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
    fn drain(
        self,
        channel: u16,
        read: impl FnMut() -> Result<ReadReport, LedgerError>,
    ) -> Result<(), ReadFailure> {
        self.advance(channel, read, |_| {})
    }
}

/// Where the device stands between exchanges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No reply is owed.
    Ready,
    /// Reports still owed from an earlier reply.
    Owed(Progress),
    /// A report broke framing, so what is owed is unknown.
    Broken,
}

/// Why reading a reply failed.
#[derive(Debug)]
enum ReadFailure {
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
    fn packetize(&self, channel: u16) -> impl Iterator<Item = WriteReport> + use<> {
        self.as_buffer().packetize(channel)
    }
}

impl ApduAnswer {
    /// Reassemble a reply from the reports `read` returns, starting at its
    /// first report. See [`ApduBuffer::depacketize`].
    fn depacketize(
        channel: u16,
        read: impl FnMut() -> Result<ReadReport, LedgerError>,
    ) -> Result<Self, ReadFailure> {
        let answer = ApduBuffer::depacketize(channel, read)?;
        Self::from_answer(answer).map_err(ReadFailure::Answer)
    }
}

/// An [`HidDevice`] that we know to be a Ledger.
///
/// # Timeouts
///
/// When an exchange times out, the rest of its reply is still coming: the
/// device sends it once the prompt on screen is resolved, and hidapi queues
/// it. Read as the answer to the next command, it would pass every framing
/// check. So the next exchange first reads and drops whatever is owed, waiting
/// up to its own timeout for each report, and only then sends its command. If
/// the owed reports do not arrive in time, it fails with
/// [`LedgerError::Timeout`] without sending anything.
///
/// A report that breaks framing leaves what is owed unknown, so a later reply
/// may be misread as the answer to a later command. [`HidTransport`] closes
/// the device when that happens. This type is deliberately low-level and does
/// not: after a framing error, reopen the device.
///
/// [`HidTransport`]: super::HidTransport
#[derive(Debug)]
pub struct HidLedgerDevice {
    device: HidDevice,
    id: HidDeviceId,
    state: State,
}

impl HidLedgerDevice {
    pub(super) const fn new(device: HidDevice, id: HidDeviceId) -> Self {
        Self {
            device,
            id,
            state: State::Ready,
        }
    }

    /// The device this handle opened.
    pub const fn id(&self) -> &HidDeviceId {
        &self.id
    }

    /// Every Ledger APDU interface attached right now. Enumerates afresh on
    /// each call.
    ///
    /// Termux cannot enumerate USB devices, so this is empty there. Use
    /// [`HidLedgerDevice::open_first`], which takes the device Termux
    /// hands over.
    ///
    /// # Panics
    ///
    /// If the HID context thread cannot be spawned, on first use.
    #[instrument(level = "debug")]
    pub fn list() -> Result<Vec<HidDeviceId>, NativeTransportError> {
        HidThread::get().submit(|reply| HidJob::List { reply })
    }

    /// Open `id`. Fails as [`NativeTransportError::CantOpen`] if the device
    /// was unplugged or another client holds it. Opens are exclusive on
    /// macOS.
    ///
    /// # Panics
    ///
    /// If the HID context thread cannot be spawned, on first use.
    #[instrument(level = "debug", skip_all, fields(id = %id))]
    pub fn open(id: &HidDeviceId) -> Result<Self, NativeTransportError> {
        HidThread::get().submit(|reply| HidJob::Open {
            id: id.clone(),
            reply,
        })
    }

    /// Open the first Ledger found. Devices are enumerated afresh on every
    /// call. Under Termux, which cannot enumerate, this opens the device
    /// `termux-usb` hands over instead.
    ///
    /// On macOS the device is opened exclusively, so this fails while another
    /// process, or another transport in this one, holds it.
    ///
    /// # Panics
    ///
    /// If the HID context thread cannot be spawned, on first use.
    #[instrument(level = "debug", fields(id))]
    pub fn open_first() -> Result<Self, NativeTransportError> {
        HidThread::get()
            .submit(|reply| HidJob::OpenFirst { reply })
            .inspect(|device| {
                Span::current().record("id", display(&device.id));
            })
    }

    /// Get manufacturer string. Returns None on error, or on no string.
    pub fn get_manufacturer_string(&self) -> Option<String> {
        self.device.get_manufacturer_string().unwrap_or_default()
    }

    /// Send `command` and read the reply, waiting up to `timeout` for each
    /// report. `None` waits indefinitely. A non-success status word is an
    /// error. The rest of an earlier, timed-out reply is dropped first; see
    /// [Timeouts](Self#timeouts).
    pub fn exchange(
        &mut self,
        command: &ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        // A broken device is not refused: what is owed is unknown, so nothing
        // is dropped.
        match self.state {
            State::Ready | State::Broken => {}
            State::Owed(owed) => {
                let drained = owed.drain(LEDGER_CHANNEL, self.reader(timeout));
                self.settle(drained)?;
                tracing::debug!("Dropped the rest of a reply to an earlier exchange");
            }
        }

        // A failed write leaves no reply owed: the device did not get a whole
        // command.
        self.write_command(command)?;
        let answer = ApduAnswer::depacketize(LEDGER_CHANNEL, self.reader(timeout));
        self.settle(answer)?.into_result()
    }

    /// Write `command` to the device as a series of reports.
    fn write_command(&self, command: &ApduCommand) -> Result<(), NativeTransportError> {
        tracing::debug!(bytes = command.as_bytes().len(), "Writing APDU to device");

        for WriteReport(report) in command.packetize(LEDGER_CHANNEL) {
            tracing::trace!(packet = %hex::encode(report), "Writing packet to device");

            let written = self.device.write(&report)?;
            if written < report.len() {
                return Err(NativeTransportError::ShortWrite {
                    written,
                    expected: report.len(),
                });
            }
        }
        Ok(())
    }

    /// Reads one report from the device per call, waiting up to `timeout`.
    fn reader(
        &self,
        timeout: Option<Duration>,
    ) -> impl FnMut() -> Result<ReadReport, LedgerError> + '_ {
        // hidapi takes milliseconds, or -1 to block. Sub-millisecond timeouts
        // round up; longer than `i32::MAX` ms clamps.
        let timeout_ms = match timeout {
            None => -1,
            Some(timeout) => timeout
                .as_micros()
                .div_ceil(1000)
                .try_into()
                .unwrap_or(i32::MAX),
        };
        move || {
            let mut bytes = [0; LEDGER_PACKET_READ_SIZE];
            let len = self
                .device
                .read_timeout(&mut bytes, timeout_ms)
                .map_err(NativeTransportError::Hid)?;
            // hidapi returns 0 only on timeout, which a blocking read rules out.
            match (len, timeout) {
                (0, Some(timeout)) => Err(LedgerError::Timeout(timeout)),
                _ => Ok(ReadReport { bytes, len }),
            }
        }
    }

    /// Record what reading a reply left owed. The state becomes
    /// [`State::Ready`] once the reply is read, even if it is not a valid
    /// answer, [`State::Owed`] with the progress made if a report cannot be
    /// read, and [`State::Broken`] if a report breaks framing.
    fn settle<T>(&mut self, result: Result<T, ReadFailure>) -> Result<T, LedgerError> {
        match result {
            Ok(read) => {
                self.state = State::Ready;
                Ok(read)
            }
            Err(ReadFailure::Read { err, owed }) => {
                self.state = State::Owed(owed);
                Err(err)
            }
            Err(ReadFailure::Framing(err)) => {
                self.state = State::Broken;
                Err(err.into())
            }
            Err(ReadFailure::Answer(err)) => {
                self.state = State::Ready;
                Err(err)
            }
        }
    }

    /// True if a report broke framing since the last whole reply, so what
    /// the device still owes is unknown.
    pub(super) fn is_broken(&self) -> bool {
        self.state == State::Broken
    }

    /// True if running under Termux, which cannot enumerate USB devices.
    /// Detected at runtime, since Termux cannot be targeted statically.
    #[cfg(target_os = "android")]
    pub(super) fn is_termux() -> bool {
        std::env::var("PREFIX").is_ok_and(|prefix| prefix.contains("/com.termux/"))
    }

    /// Open the device `termux-usb` hands over. Termux cannot enumerate USB
    /// devices; instead `termux-usb` opens the device and passes its file
    /// descriptor in `TERMUX_USB_FD`. Returns `None` when not running under
    /// Termux.
    ///
    /// Untested: no Android device is exercised in CI.
    #[cfg(target_os = "android")]
    pub(super) fn open_termux(api: &HidApi) -> Result<Option<Self>, NativeTransportError> {
        if !Self::is_termux() {
            return Ok(None);
        }

        let usb_fd: i32 = std::env::var("TERMUX_USB_FD")
            .ok()
            .and_then(|fd| fd.parse().ok())
            .ok_or(NativeTransportError::InvalidTermuxUsbFd)?;

        let device = api.wrap_sys_device(usb_fd as isize, -1)?;
        let id = HidDeviceId::from_info(&device.get_device_info()?);
        Ok(Some(Self::new(device, id)))
    }
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/native/device.rs"]
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
