//! Native HID APDU transport for Ledger Nano hardware wallets
//!
//! Packets or "reports" are individual device communications. An APDU is sent/
//! received as a series of reports.
//!
//! hidapi initializes once per process, on the first thread to create a
//! `HidApi`, and on macOS binds its device manager to that thread's run loop
//! for good. This crate therefore does all of its hidapi context work on one
//! thread that lives as long as the process; see `on_hid_thread`. An
//! application that mixes HID crates should likewise initialize hidapi once
//! from a long-lived thread, because whichever crate initializes first decides
//! where the manager lives.

use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{Mutex, PoisonError, mpsc},
    thread::ThreadId,
    time::Duration,
};

use hidapi::{DeviceInfo, HidApi, HidDevice};

use crate::{
    common::{ApduAnswer, ApduBuffer, ApduCommand},
    errors::LedgerError,
};

use super::NativeTransportError;

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;
const LEDGER_CHANNEL: u16 = 0x0101;
/// The tag byte of every APDU report.
const LEDGER_TAG: u8 = 0x05;
/// A report as written: a report ID byte, which Windows requires and the
/// other platforms tolerate, then 64 bytes.
const LEDGER_PACKET_WRITE_SIZE: usize = 65;
/// A report as read: 64 bytes.
const LEDGER_PACKET_READ_SIZE: usize = 64;

type WriteReport = [u8; LEDGER_PACKET_WRITE_SIZE];
type ReadReport = [u8; LEDGER_PACKET_READ_SIZE];

/// Native HID transport for Ledger Nano hardware wallets
pub struct TransportNativeHID {
    device: HidDevice,
}

impl std::fmt::Debug for TransportNativeHID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportNativeHID").finish()
    }
}

impl TransportNativeHID {
    /// Instantiate from a device.
    const fn from_device(device: HidDevice) -> Self {
        Self { device }
    }

    /// Open every Ledger device. Enumeration can fail as a whole; each open
    /// can fail on its own, e.g. when another process holds that device.
    pub fn open_all_devices()
    -> Result<Vec<Result<Self, NativeTransportError>>, NativeTransportError> {
        let devices = on_hid_thread(|| -> Result<Vec<_>, NativeTransportError> {
            let api = HidApi::new()?;
            Ok(list_ledgers(&api)
                .map(|dev| open_device(&api, dev))
                .collect())
        })??;
        Ok(devices
            .into_iter()
            .map(|device| device.map(Self::from_device))
            .collect())
    }

    /// Create a new HID transport, connecting to the first ledger found.
    /// Devices are enumerated afresh on every call.
    ///
    /// On macOS the device is opened exclusively, so this fails while another
    /// process, or another transport in this one, holds it.
    pub fn new() -> Result<Self, NativeTransportError> {
        on_hid_thread(|| {
            #[cfg(target_os = "android")]
            if let Some(device) = open_termux_device()? {
                return Ok(device);
            }

            let api = HidApi::new()?;
            first_ledger(&api)
        })?
        .map(Self::from_device)
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
        write_apdu(&self.device, LEDGER_CHANNEL, command.as_bytes())?;
        let answer = read_apdu(&self.device, LEDGER_CHANNEL, timeout)?;
        let answer = ApduAnswer::from_answer(answer)?;

        if answer.is_success() {
            Ok(answer)
        } else {
            Err(answer.status().into())
        }
    }
}

/// Termux cannot enumerate USB devices. Instead `termux-usb` opens the device
/// and hands over its file descriptor in `TERMUX_USB_FD`. Returns `None`
/// when not running under Termux.
///
/// Untested: no Android device is exercised in CI.
#[cfg(target_os = "android")]
fn open_termux_device() -> Result<Option<HidDevice>, NativeTransportError> {
    // Using runtime detection since it's impossible to statically target Termux.
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
    Ok(Some(api.wrap_sys_device(usb_fd as isize, -1)?))
}

type HidJob = Box<dyn FnOnce() + Send>;

/// The thread that runs every hidapi context call, started on first use and
/// kept for the life of the process.
fn hid_thread() -> Result<(mpsc::Sender<HidJob>, ThreadId), NativeTransportError> {
    static HID_THREAD: Mutex<Option<(mpsc::Sender<HidJob>, ThreadId)>> = Mutex::new(None);

    let mut slot = HID_THREAD.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(thread) = &*slot {
        return Ok(thread.clone());
    }
    let (tx, rx) = mpsc::channel::<HidJob>();
    let handle = std::thread::Builder::new()
        .name("coins-ledger-hid".into())
        .spawn(move || {
            for job in rx {
                job();
            }
        })
        .map_err(|_| NativeTransportError::HidThreadUnavailable)?;
    let thread = (tx, handle.thread().id());
    *slot = Some(thread.clone());
    Ok(thread)
}

/// Run `f` on the HID context thread and wait for its result. A panic in
/// `f` is propagated to the caller. A call made from the context thread
/// itself runs inline.
///
/// hidapi's macOS backend schedules its global device manager on the run
/// loop of the thread that first initializes it, and holds that run loop
/// unretained. If the thread exits while another thread is enumerating, the
/// run loop is freed mid-enumeration and the process traps. Keeping one
/// thread alive for the life of the process, and doing every context call
/// there, avoids that. Device I/O does not touch the manager and stays on
/// the caller's thread.
fn on_hid_thread<R: Send + 'static>(
    f: impl FnOnce() -> R + Send + 'static,
) -> Result<R, NativeTransportError> {
    let (jobs, id) = hid_thread()?;
    if std::thread::current().id() == id {
        return Ok(f());
    }

    let (tx, rx) = mpsc::channel();
    jobs.send(Box::new(move || {
        let _ = tx.send(catch_unwind(AssertUnwindSafe(f)));
    }))
    .map_err(|_| NativeTransportError::HidThreadUnavailable)?;
    match rx.recv() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(panic)) => resume_unwind(panic),
        Err(_) => Err(NativeTransportError::HidThreadUnavailable),
    }
}

/// True if a HID interface is the APDU interface of a Ledger device.
///
/// The usage page identifies it wherever hidapi reports one. On Linux, older
/// hidapi builds report no usage page, so interface 0 is accepted as well.
/// This mirrors the filter in Ledger's own transports. The FIDO interface a
/// device exposes alongside is rejected either way.
const fn is_ledger_interface(vendor_id: u16, usage_page: u16, interface_number: i32) -> bool {
    let apdu_interface =
        usage_page == LEDGER_USAGE_PAGE || (cfg!(target_os = "linux") && interface_number == 0);
    vendor_id == LEDGER_VID && apdu_interface
}

fn is_ledger(dev: &DeviceInfo) -> bool {
    is_ledger_interface(dev.vendor_id(), dev.usage_page(), dev.interface_number())
}

/// Get a list of ledger devices available
fn list_ledgers(api: &HidApi) -> impl Iterator<Item = &DeviceInfo> {
    api.device_list().filter(|dev| is_ledger(dev))
}

#[tracing::instrument(level = "trace", skip_all, err)]
fn first_ledger(api: &HidApi) -> Result<HidDevice, NativeTransportError> {
    let device = list_ledgers(api)
        .next()
        .ok_or(NativeTransportError::DeviceNotFound)?;

    open_device(api, device)
}

/// Convert a per-report timeout to hidapi's representation: milliseconds, or
/// -1 to block until a report arrives. Durations over `i32::MAX` ms are
/// clamped.
fn hid_timeout_ms(timeout: Option<Duration>) -> i32 {
    match timeout {
        None => -1,
        Some(timeout) => timeout.as_millis().try_into().unwrap_or(i32::MAX),
    }
}

/// Copy `src` to the start of `dst` and zero the rest. `src` must fit.
fn fill(dst: &mut [u8], src: &[u8]) {
    dst[..src.len()].copy_from_slice(src);
    dst[src.len()..].fill(0);
}

/// Split an APDU into HID reports and pass each to `sink`. The first report
/// carries the 2-byte APDU length ahead of the payload.
fn packetize(
    channel: u16,
    apdu: &[u8],
    mut sink: impl FnMut(&WriteReport) -> Result<(), NativeTransportError>,
) -> Result<(), NativeTransportError> {
    let apdu_len = u16::try_from(apdu.len())
        .map_err(|_| NativeTransportError::Comm("APDU too long for HID framing"))?;

    let mut packet = [0u8; LEDGER_PACKET_WRITE_SIZE];
    packet[1..3].copy_from_slice(&channel.to_be_bytes());
    packet[3] = LEDGER_TAG;

    // The first report has sequence index 0 and leads with the APDU length.
    let (first, rest) = apdu.split_at(apdu.len().min(LEDGER_PACKET_WRITE_SIZE - 8));
    packet[6..8].copy_from_slice(&apdu_len.to_be_bytes());
    fill(&mut packet[8..], first);
    sink(&packet)?;

    for (i, chunk) in rest.chunks(LEDGER_PACKET_WRITE_SIZE - 6).enumerate() {
        packet[4..6].copy_from_slice(&((i + 1) as u16).to_be_bytes());
        fill(&mut packet[6..], chunk);
        sink(&packet)?;
    }
    Ok(())
}

/// Write an APDU to the device as a series of reports.
fn write_apdu(device: &HidDevice, channel: u16, apdu: &[u8]) -> Result<(), NativeTransportError> {
    tracing::debug!(apdu = %hex::encode(apdu), bytes = apdu.len(), "Writing APDU to device");

    packetize(channel, apdu, |packet| {
        tracing::trace!(packet = %hex::encode(packet), "Writing packet to device");

        let written = device.write(packet).map_err(NativeTransportError::Hid)?;

        if written < packet.len() {
            return Err(NativeTransportError::ShortWrite {
                written,
                expected: packet.len(),
            });
        }
        Ok(())
    })
}

/// Read one report from `source` and check its framing: channel, tag, and
/// sequence index. Returns the number of bytes in the report.
fn read_report(
    source: &mut impl FnMut(&mut ReadReport) -> Result<usize, NativeTransportError>,
    report: &mut ReadReport,
    channel: u16,
    sequence_idx: u16,
) -> Result<usize, NativeTransportError> {
    tracing::trace!(sequence_idx, "Reading report from device");
    let n = source(report)?;
    if n < 5 {
        return Err(NativeTransportError::TruncatedReport(n));
    }

    // Another channel means another client is talking to the device.
    let got = u16::from_be_bytes([report[0], report[1]]);
    if got != channel {
        return Err(NativeTransportError::UnexpectedChannel {
            got,
            expected: channel,
        });
    }
    if report[2] != LEDGER_TAG {
        return Err(NativeTransportError::UnexpectedTag(report[2]));
    }

    // A mismatch means someone else read a report.
    let got = u16::from_be_bytes([report[3], report[4]]);
    if got != sequence_idx {
        return Err(NativeTransportError::SequenceMismatch {
            got,
            expected: sequence_idx,
        });
    }
    Ok(n)
}

/// Reassemble a response APDU from the reports `source` yields. The first
/// report carries the 2-byte response length ahead of the payload.
fn depacketize(
    channel: u16,
    mut source: impl FnMut(&mut ReadReport) -> Result<usize, NativeTransportError>,
) -> Result<ApduBuffer, NativeTransportError> {
    let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
    let mut answer = ApduBuffer::new();

    // The first report has sequence index 0 and leads with the response length.
    let n = read_report(&mut source, &mut report, channel, 0)?;
    if n < 7 {
        return Err(NativeTransportError::TruncatedReport(n));
    }
    let expected = u16::from_be_bytes([report[5], report[6]]) as usize;
    tracing::trace!(expected, "Received response length from device");
    if expected > ApduBuffer::CAPACITY {
        return Err(NativeTransportError::ResponseTooLong(expected));
    }

    // Only the bytes the device sent are payload. The rest of the report
    // array is stale.
    let chunk = &report[7..n.min(7 + expected)];
    answer
        .extend_from_slice(chunk)
        .map_err(|_| NativeTransportError::ResponseTooLong(expected))?;

    let mut sequence_idx = 1;
    while answer.len() < expected {
        let n = read_report(&mut source, &mut report, channel, sequence_idx)?;
        let chunk = &report[5..n.min(5 + expected - answer.len())];
        if chunk.is_empty() {
            return Err(NativeTransportError::EmptyReport);
        }
        answer
            .extend_from_slice(chunk)
            .map_err(|_| NativeTransportError::ResponseTooLong(expected))?;
        sequence_idx += 1;
    }
    Ok(answer)
}

/// Read a response APDU from the device, waiting up to `timeout` for each
/// report.
fn read_apdu(
    device: &HidDevice,
    channel: u16,
    timeout: Option<Duration>,
) -> Result<ApduBuffer, NativeTransportError> {
    let timeout_ms = hid_timeout_ms(timeout);
    depacketize(channel, |report| {
        let n = device.read_timeout(report, timeout_ms)?;
        if n == 0 {
            return Err(match timeout {
                Some(timeout) => NativeTransportError::Timeout(timeout),
                None => NativeTransportError::TruncatedReport(0),
            });
        }
        Ok(n)
    })
}

/// Open a specific device. No check is made that it is a Ledger.
///
/// On macOS the open is exclusive and fails while another client holds the
/// device.
fn open_device(api: &HidApi, device: &DeviceInfo) -> Result<HidDevice, NativeTransportError> {
    let device = device
        .open_device(api)
        .map_err(NativeTransportError::CantOpen)?;
    if let Err(err) = device.set_blocking_mode(true) {
        // hidapi opens devices in blocking mode, so this is not fatal.
        tracing::trace!(%err, "Could not set blocking mode on device");
    }

    Ok(device)
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/native/hid.rs"]
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
