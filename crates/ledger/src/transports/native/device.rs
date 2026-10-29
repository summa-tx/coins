//! A Ledger's APDU interface over native HID.
//!
//! Packets or "reports" are individual device communications. An APDU is sent/
//! received as a series of reports.

use std::time::Duration;

#[cfg(target_os = "android")]
use hidapi::HidApi;
use hidapi::HidDevice;
use tracing::{Span, field::display, instrument};

use super::hid::{HidDeviceId, HidJob, HidOutput};
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

/// A report as written: a report ID byte, then the channel, tag, sequence
/// index, and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteReport([u8; LEDGER_PACKET_WRITE_SIZE]);

impl WriteReport {
    /// Split an APDU into reports and pass each to `sink`. The reports carry
    /// the 2-byte APDU length, then the APDU. `apdu` is at most
    /// [`ApduBuffer::CAPACITY`] bytes.
    fn packetize(
        channel: u16,
        apdu: &[u8],
        mut sink: impl FnMut(&Self) -> Result<(), NativeTransportError>,
    ) -> Result<(), NativeTransportError> {
        let mut stream = [0u8; 2 + ApduBuffer::CAPACITY];
        let len = 2 + apdu.len();
        stream[..2].copy_from_slice(&(apdu.len() as u16).to_be_bytes());
        stream[2..len].copy_from_slice(apdu);

        let mut report = Self([0; LEDGER_PACKET_WRITE_SIZE]);
        report.0[1..3].copy_from_slice(&channel.to_be_bytes());
        report.0[3] = LEDGER_TAG;
        for (i, chunk) in stream[..len]
            .chunks(LEDGER_PACKET_WRITE_SIZE - 6)
            .enumerate()
        {
            report.0[4..6].copy_from_slice(&(i as u16).to_be_bytes());
            // Zero the tail, which still holds the previous chunk.
            let (payload, tail) = report.0[6..].split_at_mut(chunk.len());
            payload.copy_from_slice(chunk);
            tail.fill(0);
            sink(&report)?;
        }
        Ok(())
    }
}

/// A report as read, with its framing checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadReport {
    bytes: [u8; LEDGER_PACKET_READ_SIZE],
    /// The bytes the device sent. The rest of `bytes` is stale.
    len: usize,
}

impl ReadReport {
    /// Read one report from `source` and check its framing: channel, tag,
    /// and sequence index. `source` fills the array and returns the bytes
    /// read.
    ///
    /// Generic over the error so that a source can report its own failures
    /// apart from framing errors, which are [`NativeTransportError`]s.
    fn read<E: From<NativeTransportError>>(
        source: &mut impl FnMut(&mut [u8; LEDGER_PACKET_READ_SIZE]) -> Result<usize, E>,
        channel: u16,
        sequence_idx: u16,
    ) -> Result<Self, E> {
        tracing::trace!(sequence_idx, "Reading report from device");
        let mut bytes = [0; LEDGER_PACKET_READ_SIZE];
        let len = source(&mut bytes)?;
        if len < 5 {
            return Err(NativeTransportError::TruncatedReport(len).into());
        }

        // Another channel means another client is talking to the device.
        let got = u16::from_be_bytes([bytes[0], bytes[1]]);
        if got != channel {
            return Err(NativeTransportError::UnexpectedChannel {
                got,
                expected: channel,
            }
            .into());
        }
        if bytes[2] != LEDGER_TAG {
            return Err(NativeTransportError::UnexpectedTag(bytes[2]).into());
        }

        // A mismatch means someone else read a report.
        let got = u16::from_be_bytes([bytes[3], bytes[4]]);
        if got != sequence_idx {
            return Err(NativeTransportError::SequenceMismatch {
                got,
                expected: sequence_idx,
            }
            .into());
        }
        Ok(Self { bytes, len })
    }

    /// The bytes the device sent after the 5-byte header.
    fn body(&self) -> &[u8] {
        &self.bytes[5..self.len]
    }
}

/// How far reassembly of a reply has got.
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

    /// Reassemble the rest of the reply from the reports `source` yields, and
    /// return the payload read. The first report carries the 2-byte response
    /// length ahead of the payload. Advances with each report taken, so a
    /// failed read can resume.
    fn depacketize<E: From<NativeTransportError>>(
        &mut self,
        channel: u16,
        mut source: impl FnMut(&mut [u8; LEDGER_PACKET_READ_SIZE]) -> Result<usize, E>,
    ) -> Result<ApduBuffer, E> {
        let mut answer = ApduBuffer::new();
        loop {
            let report = ReadReport::read(&mut source, channel, self.next_seq)?;
            let payload = if self.next_seq == 0 {
                let [hi, lo, payload @ ..] = report.body() else {
                    return Err(NativeTransportError::TruncatedReport(report.len).into());
                };
                let expected = u16::from_be_bytes([*hi, *lo]) as usize;
                tracing::trace!(expected, "Received response length from device");
                if expected > ApduBuffer::CAPACITY {
                    return Err(NativeTransportError::ResponseTooLong(expected).into());
                }
                self.remaining = expected;
                payload
            } else if report.body().is_empty() {
                return Err(NativeTransportError::EmptyReport.into());
            } else {
                report.body()
            };

            let take = payload.len().min(self.remaining);
            answer
                .extend_from_slice(&payload[..take])
                .expect("a reply fits in an ApduBuffer");
            self.remaining -= take;
            self.next_seq += 1;
            if self.remaining == 0 {
                return Ok(answer);
            }
        }
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
enum ReadFailure {
    /// A report could not be read. What is owed is still known.
    Read(LedgerError),
    /// A report broke framing.
    Framing(NativeTransportError),
}

impl From<NativeTransportError> for ReadFailure {
    fn from(err: NativeTransportError) -> Self {
        Self::Framing(err)
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
        HidJob::List.submit().map(HidOutput::into_ids)
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
        HidJob::Open(id.clone())
            .submit()
            .map(HidOutput::into_device)
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
        HidJob::OpenFirst
            .submit()
            .map(HidOutput::into_device)
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
            State::Owed(progress) => {
                self.read_reply(progress, timeout)?;
                tracing::debug!("Dropped the rest of a reply to an earlier exchange");
            }
        }

        // A failed write leaves no reply owed: the device did not get a whole
        // command.
        self.write_apdu(command.as_bytes())?;
        let answer = self.read_reply(Progress::START, timeout)?;
        ApduAnswer::from_answer(answer)?.into_result()
    }

    /// Write an APDU to the device as a series of reports.
    fn write_apdu(&self, apdu: &[u8]) -> Result<(), NativeTransportError> {
        tracing::debug!(bytes = apdu.len(), "Writing APDU to device");

        WriteReport::packetize(LEDGER_CHANNEL, apdu, |WriteReport(report)| {
            tracing::trace!(packet = %hex::encode(report), "Writing packet to device");

            let written = self.device.write(report)?;
            if written < report.len() {
                return Err(NativeTransportError::ShortWrite {
                    written,
                    expected: report.len(),
                });
            }
            Ok(())
        })
    }

    /// Read the rest of the reply `progress` describes, waiting up to
    /// `timeout` for each report, and return the payload read. The state
    /// becomes [`State::Ready`] once the reply is read, [`State::Owed`] with
    /// the progress made if a report cannot be read, and [`State::Broken`] if
    /// a report breaks framing.
    fn read_reply(
        &mut self,
        mut progress: Progress,
        timeout: Option<Duration>,
    ) -> Result<ApduBuffer, LedgerError> {
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
        let device = &self.device;
        let result = progress.depacketize(LEDGER_CHANNEL, |report| {
            let n = device
                .read_timeout(report, timeout_ms)
                .map_err(|err| ReadFailure::Read(NativeTransportError::Hid(err).into()))?;
            // hidapi returns 0 only on timeout, which a blocking read rules out.
            match (n, timeout) {
                (0, Some(timeout)) => Err(ReadFailure::Read(LedgerError::Timeout(timeout))),
                _ => Ok(n),
            }
        });
        match result {
            Ok(answer) => {
                self.state = State::Ready;
                Ok(answer)
            }
            Err(ReadFailure::Read(err)) => {
                self.state = State::Owed(progress);
                Err(err)
            }
            Err(ReadFailure::Framing(err)) => {
                self.state = State::Broken;
                Err(err.into())
            }
        }
    }

    /// True if a report broke framing since the last whole reply, so what
    /// the device still owes is unknown.
    pub(super) fn is_broken(&self) -> bool {
        self.state == State::Broken
    }

    /// Open the device `termux-usb` hands over. Termux cannot enumerate USB
    /// devices; instead `termux-usb` opens the device and passes its file
    /// descriptor in `TERMUX_USB_FD`. Returns `None` when not running under
    /// Termux.
    ///
    /// Untested: no Android device is exercised in CI.
    #[cfg(target_os = "android")]
    fn open_termux() -> Result<Option<Self>, NativeTransportError> {
        // Using runtime detection since it's impossible to statically target
        // Termux.
        let is_termux = std::env::var("PREFIX").is_ok_and(|prefix| prefix.contains("/com.termux/"));
        if !is_termux {
            return Ok(None);
        }

        let usb_fd: i32 = std::env::var("TERMUX_USB_FD")
            .ok()
            .and_then(|fd| fd.parse().ok())
            .ok_or(NativeTransportError::InvalidTermuxUsbFd)?;

        // Enumeration needs USB authority Termux does not have. This panics if
        // hidapi was already initialized with discovery on by other code in the
        // process.
        HidApi::disable_device_discovery();
        let api = HidApi::new()?;
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
