//! A Ledger's APDU interface over native HID: opening the device and running
//! exchanges on it. Report framing lives in [`super::report`].

use std::time::Duration;

#[cfg(target_os = "android")]
use hidapi::HidApi;
use hidapi::HidDevice;
use tracing::{Span, field::display, instrument};

use super::{
    hid::{HidDeviceId, HidJob, HidThread},
    report::{LEDGER_CHANNEL, LEDGER_PACKET_READ_SIZE, Payload, Progress, ReadReport, WriteReport},
};
use crate::{
    common::{ApduAnswer, ApduBuffer, ApduCommand},
    errors::LedgerError,
    transports::native::error::NativeTransportError,
};

/// Where the device stands between exchanges. When an exchange times out,
/// the device still sends the rest of its reply once the prompt is resolved,
/// and hidapi queues it. It would pass every framing check as the answer to
/// the next command, so that exchange drops it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No reply is owed.
    Ready,
    /// Reports still owed from an earlier reply.
    Owed(Progress),
    /// A report broke framing, so what is owed is unknown.
    Broken,
}

/// A blocking HID connection to a Ledger. Exchanges run on the caller's
/// thread. For async use, open a [`HidTransport`] instead.
///
/// After an exchange times out, the next one may also time out without
/// sending its command, while the device finishes the earlier reply. After
/// any other [`NativeTransportError`], reopen the device.
///
/// Whether other clients can use the device meanwhile depends on the
/// platform. See [Exclusive access](crate::transports::HidTransport#exclusive-access).
///
/// [`HidTransport`]: crate::transports::HidTransport
// Public only with `sync-hid`; otherwise the crate uses it internally.
#[cfg_attr(not(feature = "sync-hid"), allow(unreachable_pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "sync-hid")))]
#[derive(Debug)]
pub struct HidLedgerDevice {
    device: HidDevice,
    id: HidDeviceId,
    state: State,
}

#[cfg_attr(not(feature = "sync-hid"), allow(unreachable_pub))]
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
    /// On Android under Termux, which cannot enumerate USB devices, this is
    /// empty. Use [`HidLedgerDevice::open_first`], which takes the device
    /// Termux hands over.
    ///
    /// # Panics
    ///
    /// On first use, if a background thread cannot be spawned.
    #[instrument(level = "debug")]
    pub fn list() -> Result<Vec<HidDeviceId>, NativeTransportError> {
        HidThread::get().submit(|reply| HidJob::List { reply })
    }

    /// Open `id`. Fails as [`NativeTransportError::CantOpen`] if the device
    /// was unplugged, or another client holds it where opens are
    /// [exclusive](crate::transports::HidTransport#exclusive-access).
    ///
    /// # Panics
    ///
    /// On first use, if a background thread cannot be spawned.
    #[instrument(level = "debug", skip_all, fields(id = %id))]
    pub fn open(id: &HidDeviceId) -> Result<Self, NativeTransportError> {
        HidThread::get().submit(|reply| HidJob::Open {
            id: id.clone(),
            reply,
        })
    }

    /// Open the first Ledger found. Devices are enumerated afresh on every
    /// call. On Android under Termux, which cannot enumerate, this opens the
    /// device `termux-usb` hands over instead.
    ///
    /// Where opens are [exclusive](crate::transports::HidTransport#exclusive-access), this fails
    /// while another client, or another handle in this process, holds it.
    ///
    /// # Panics
    ///
    /// On first use, if a background thread cannot be spawned.
    #[instrument(level = "debug", fields(id))]
    pub fn open_first() -> Result<Self, NativeTransportError> {
        HidThread::get()
            .submit(|reply| HidJob::OpenFirst { reply })
            .inspect(|device| {
                Span::current().record("id", display(&device.id));
            })
    }

    /// Send `command` and read the reply, waiting up to `timeout` for each
    /// report. `None` waits indefinitely. A non-success status word is an
    /// error.
    pub fn exchange(
        &mut self,
        command: &ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        // A broken device is not refused: what is owed is unknown, so nothing
        // is dropped.
        if let State::Owed(owed) = self.state {
            self.read_reply(owed, timeout, &mut ApduBuffer::new())?;
            tracing::debug!("Dropped the rest of a reply to an earlier exchange");
        }

        // A failed write leaves no reply owed: the device did not get a whole
        // command.
        self.write_command(command)?;
        let mut answer = ApduBuffer::new();
        self.read_reply(Progress::START, timeout, &mut answer)?;
        ApduAnswer::from_answer(answer)?.into_result()
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

    /// Read the rest of a reply into `buf`, starting from `progress`, and
    /// record what the device still owes. The state becomes [`State::Ready`]
    /// once the reply is read, [`State::Owed`] with the progress made if a
    /// report cannot be read, and [`State::Broken`] if a report breaks
    /// framing.
    fn read_reply(
        &mut self,
        progress: Progress,
        timeout: Option<Duration>,
        buf: &mut ApduBuffer,
    ) -> Result<(), LedgerError> {
        let mut reply = Reply {
            device: &self.device,
            timeout,
            progress,
            failed: false,
        };
        while let Some(payload) = reply.next() {
            match payload {
                Ok(payload) => buf
                    .extend_from_slice(&payload)
                    .expect("a reply is capped at CAPACITY"),
                Err(ReadFailure::Read(err)) => {
                    self.state = State::Owed(reply.progress);
                    return Err(err);
                }
                Err(ReadFailure::Framing(err)) => {
                    self.state = State::Broken;
                    return Err(err.into());
                }
            }
        }
        self.state = State::Ready;
        Ok(())
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

/// Why reading a report of a reply failed.
#[derive(Debug)]
enum ReadFailure {
    /// The report could not be read. It may yet arrive.
    Read(LedgerError),
    /// The report broke framing.
    Framing(NativeTransportError),
}

/// The payload of one reply, a report at a time. Ends when the reply is
/// complete, or after the first error.
#[derive(Debug)]
struct Reply<'a> {
    device: &'a HidDevice,
    /// How long to wait for each report. `None` waits indefinitely.
    timeout: Option<Duration>,
    progress: Progress,
    failed: bool,
}

impl Reply<'_> {
    /// Read one report from the device, waiting up to `timeout`.
    fn read_report(&self) -> Result<ReadReport, LedgerError> {
        // hidapi takes milliseconds, or -1 to block. Sub-millisecond timeouts
        // round up; longer than `i32::MAX` ms clamps.
        let timeout_ms = match self.timeout {
            None => -1,
            Some(timeout) => timeout
                .as_micros()
                .div_ceil(1000)
                .try_into()
                .unwrap_or(i32::MAX),
        };

        let mut bytes = [0; LEDGER_PACKET_READ_SIZE];
        let len = self
            .device
            .read_timeout(&mut bytes, timeout_ms)
            .map_err(NativeTransportError::Hid)?;

        // hidapi returns 0 only on timeout, which a blocking read rules out.
        match (len, self.timeout) {
            (0, Some(timeout)) => Err(LedgerError::Timeout(timeout)),
            _ => Ok(ReadReport { bytes, len }),
        }
    }
}

impl Iterator for Reply<'_> {
    type Item = Result<Payload, ReadFailure>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.progress.is_done() {
            return None;
        }

        tracing::trace!(progress = ?self.progress, "Reading report from device");
        let payload = match self.read_report() {
            Ok(report) => self
                .progress
                .accept(LEDGER_CHANNEL, report)
                .map_err(ReadFailure::Framing),
            Err(err) => Err(ReadFailure::Read(err)),
        };
        self.failed = payload.is_err();
        Some(payload)
    }
}

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
