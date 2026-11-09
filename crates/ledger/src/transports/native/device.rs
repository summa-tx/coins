//! A Ledger's APDU interface over native HID: opening the device and running
//! exchanges on it. Report framing lives in [`super::report`].

use std::time::Duration;

#[cfg(target_os = "android")]
use hidapi::HidApi;
use hidapi::HidDevice;
use tracing::{Span, field::display, instrument};

use super::{
    hid::{HidDeviceId, HidJob, HidThread},
    report::{
        LEDGER_CHANNEL, LEDGER_PACKET_READ_SIZE, Progress, ReadFailure, ReadReport, WriteReport,
    },
};
use crate::{
    common::{ApduAnswer, ApduCommand},
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

/// An [`HidDevice`] that we know to be a Ledger.
///
/// After an exchange times out, the next one may also time out without
/// sending its command, while the device finishes the earlier reply. After
/// any other [`NativeTransportError`], reopen the device.
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
    /// On first use, if a background thread cannot be spawned.
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
    /// On first use, if a background thread cannot be spawned.
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
    /// On first use, if a background thread cannot be spawned.
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
    /// error.
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
