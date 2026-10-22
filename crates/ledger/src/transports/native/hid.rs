//! Native HID APDU transport for Ledger Nano hardware wallets
//!
//! Packets or "reports" are individual device communications. An APDU is sent/
//! received as a series of reports.
//!
//! Every hidapi context call runs on one thread that lives as long as the
//! process; `on_hid_thread` explains why. An application that mixes HID
//! crates should likewise initialize hidapi once from a long-lived thread,
//! because whichever crate initializes first decides where hidapi's device
//! manager lives.

use std::{
    ffi::{CStr, CString},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{Mutex, PoisonError, mpsc},
    thread::ThreadId,
    time::Duration,
};

use hidapi::{DeviceInfo, HidApi, HidDevice};
use tracing::{Span, field::display, instrument};

use crate::{
    Model,
    common::{ApduAnswer, ApduBuffer, ApduCommand},
    errors::LedgerError,
    transports::native::error::NativeTransportError,
};

type HidJob = Box<dyn FnOnce() + Send>;

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

/// A connected Ledger's APDU interface, as [`HidLedgerDevice::list`]
/// found it. Opens the device via [`HidLedgerDevice::open`]. Valid until
/// the device is unplugged; the path is reassigned on the next plug-in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HidDeviceId {
    /// What hidapi opens. Platform-specific and opaque.
    path: CString,
    product_id: u16,
    serial_number: Option<String>,
    product_string: Option<String>,
}

impl HidDeviceId {
    fn from_info(info: &DeviceInfo) -> Self {
        Self {
            path: info.path().to_owned(),
            product_id: info.product_id(),
            serial_number: info.serial_number().map(str::to_owned),
            product_string: info.product_string().map(str::to_owned),
        }
    }

    /// The hardware model, from the product ID.
    pub const fn model(&self) -> Model {
        Model::from_product_id(self.product_id)
    }

    /// The USB product ID.
    pub const fn product_id(&self) -> u16 {
        self.product_id
    }

    /// The serial number, if the device reports one.
    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }

    /// The product string, e.g. "Nano X".
    pub fn product_string(&self) -> Option<&str> {
        self.product_string.as_deref()
    }

    /// The platform HID path. Opaque; differs per OS and per plug-in.
    pub fn path(&self) -> &CStr {
        &self.path
    }
}

/// `Nano X (0001)`, or `Nano X` with no serial number.
impl fmt::Display for HidDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.model())?;
        if let Some(serial) = self.serial_number() {
            write!(f, " ({serial})")?;
        }
        Ok(())
    }
}

/// An [`HidDevice`] that we know to be a Ledger.
#[derive(Debug)]
pub struct HidLedgerDevice {
    device: HidDevice,
    id: HidDeviceId,
}

impl HidLedgerDevice {
    /// The device this handle opened.
    pub const fn id(&self) -> &HidDeviceId {
        &self.id
    }

    /// Split into the open handle and its ID.
    pub(super) fn into_parts(self) -> (HidDevice, HidDeviceId) {
        (self.device, self.id)
    }

    /// Every Ledger APDU interface attached right now. Enumerates afresh on
    /// each call.
    ///
    /// Termux cannot enumerate USB devices, so this is empty there. Use
    /// [`HidLedgerDevice::open_first`], which takes the device Termux
    /// hands over.
    #[instrument(level = "debug")]
    pub fn list() -> Result<Vec<HidDeviceId>, NativeTransportError> {
        on_hid_thread(|| {
            let api = HidApi::new()?;
            Ok(list_ledgers(&api).map(HidDeviceId::from_info).collect())
        })?
    }

    /// Open `id`. Fails as [`NativeTransportError::CantOpen`] if the device
    /// was unplugged or another client holds it. Opens are exclusive on
    /// macOS.
    #[instrument(level = "debug", skip_all, fields(id = %id))]
    pub fn open(id: &HidDeviceId) -> Result<Self, NativeTransportError> {
        let id = id.clone();
        on_hid_thread(move || {
            let device = HidApi::new()?
                .open_path(&id.path)
                .map_err(NativeTransportError::CantOpen)?;
            Ok(Self { device, id })
        })?
    }

    /// Open the first Ledger found. Devices are enumerated afresh on every
    /// call. Under Termux, which cannot enumerate, this opens the device
    /// `termux-usb` hands over instead.
    ///
    /// On macOS the device is opened exclusively, so this fails while another
    /// process, or another transport in this one, holds it.
    #[instrument(level = "debug", fields(id))]
    pub fn open_first() -> Result<Self, NativeTransportError> {
        on_hid_thread(|| {
            #[cfg(target_os = "android")]
            if let Some(device) = open_termux_device()? {
                return Ok(device);
            }

            let api = HidApi::new()?;
            let info = list_ledgers(&api)
                .next()
                .ok_or(NativeTransportError::DeviceNotFound)?;
            let device = info
                .open_device(&api)
                .map_err(NativeTransportError::CantOpen)?;
            Ok(Self {
                device,
                id: HidDeviceId::from_info(info),
            })
        })?
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
        exchange(&self.device, command, timeout)
    }
}

/// Termux cannot enumerate USB devices. Instead `termux-usb` opens the device
/// and hands over its file descriptor in `TERMUX_USB_FD`. Returns `None`
/// when not running under Termux.
///
/// Untested: no Android device is exercised in CI.
#[cfg(target_os = "android")]
fn open_termux_device() -> Result<Option<HidLedgerDevice>, NativeTransportError> {
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
    let device = api.wrap_sys_device(usb_fd as isize, -1)?;
    let id = HidDeviceId::from_info(&device.get_device_info()?);
    Ok(Some(HidLedgerDevice { device, id }))
}

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

/// Run `f` on the HID context thread, inside the caller's current span, and
/// wait for its result. A panic in `f` is propagated to the caller. A call
/// made from the context thread itself runs inline.
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

    let span = Span::current();
    let (tx, rx) = mpsc::channel();
    jobs.send(Box::new(move || {
        let _ = tx.send(catch_unwind(AssertUnwindSafe(|| span.in_scope(f))));
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

/// Get a list of ledger devices available
fn list_ledgers(api: &HidApi) -> impl Iterator<Item = &DeviceInfo> {
    api.device_list().filter(|dev| {
        is_ledger_interface(dev.vendor_id(), dev.usage_page(), dev.interface_number())
    })
}

/// Convert a per-report timeout to hidapi's representation: milliseconds, or
/// -1 to block until a report arrives. Sub-millisecond timeouts round up;
/// durations over `i32::MAX` ms are clamped.
fn hid_timeout_ms(timeout: Option<Duration>) -> i32 {
    match timeout {
        None => -1,
        Some(timeout) => timeout
            .as_micros()
            .div_ceil(1000)
            .try_into()
            .unwrap_or(i32::MAX),
    }
}

/// Copy `src` to the start of `dst` and zero the rest. `src` must fit.
fn fill(dst: &mut [u8], src: &[u8]) {
    dst[..src.len()].copy_from_slice(src);
    dst[src.len()..].fill(0);
}

/// Split an APDU into HID reports and pass each to `sink`. The reports carry
/// the 2-byte APDU length, then the APDU. `apdu` is at most
/// [`ApduBuffer::CAPACITY`] bytes.
fn packetize(
    channel: u16,
    apdu: &[u8],
    mut sink: impl FnMut(&WriteReport) -> Result<(), NativeTransportError>,
) -> Result<(), NativeTransportError> {
    let mut stream = [0u8; 2 + ApduBuffer::CAPACITY];
    let len = 2 + apdu.len();
    stream[..2].copy_from_slice(&(apdu.len() as u16).to_be_bytes());
    stream[2..len].copy_from_slice(apdu);

    let mut packet = [0u8; LEDGER_PACKET_WRITE_SIZE];
    packet[1..3].copy_from_slice(&channel.to_be_bytes());
    packet[3] = LEDGER_TAG;
    for (i, chunk) in stream[..len]
        .chunks(LEDGER_PACKET_WRITE_SIZE - 6)
        .enumerate()
    {
        packet[4..6].copy_from_slice(&(i as u16).to_be_bytes());
        fill(&mut packet[6..], chunk);
        sink(&packet)?;
    }
    Ok(())
}

/// Write an APDU to the device as a series of reports.
fn write_apdu(device: &HidDevice, channel: u16, apdu: &[u8]) -> Result<(), NativeTransportError> {
    tracing::debug!(bytes = apdu.len(), "Writing APDU to device");

    packetize(channel, apdu, |packet| {
        tracing::trace!(packet = %hex::encode(packet), "Writing packet to device");

        let written = device.write(packet)?;
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
///
/// Generic over the error so that a source can report a timeout as a
/// [`LedgerError`] while framing errors stay [`NativeTransportError`]s.
fn read_report<E: From<NativeTransportError>>(
    source: &mut impl FnMut(&mut ReadReport) -> Result<usize, E>,
    report: &mut ReadReport,
    channel: u16,
    sequence_idx: u16,
) -> Result<usize, E> {
    tracing::trace!(sequence_idx, "Reading report from device");
    let n = source(report)?;
    if n < 5 {
        return Err(NativeTransportError::TruncatedReport(n).into());
    }

    // Another channel means another client is talking to the device.
    let got = u16::from_be_bytes([report[0], report[1]]);
    if got != channel {
        return Err(NativeTransportError::UnexpectedChannel {
            got,
            expected: channel,
        }
        .into());
    }
    if report[2] != LEDGER_TAG {
        return Err(NativeTransportError::UnexpectedTag(report[2]).into());
    }

    // A mismatch means someone else read a report.
    let got = u16::from_be_bytes([report[3], report[4]]);
    if got != sequence_idx {
        return Err(NativeTransportError::SequenceMismatch {
            got,
            expected: sequence_idx,
        }
        .into());
    }
    Ok(n)
}

/// Reassemble a response APDU from the reports `source` yields. The first
/// report carries the 2-byte response length ahead of the payload.
fn depacketize<E: From<NativeTransportError>>(
    channel: u16,
    mut source: impl FnMut(&mut ReadReport) -> Result<usize, E>,
) -> Result<ApduBuffer, E> {
    let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
    let mut answer = ApduBuffer::new();

    // The first report has sequence index 0 and leads with the response length.
    let n = read_report(&mut source, &mut report, channel, 0)?;
    if n < 7 {
        return Err(NativeTransportError::TruncatedReport(n).into());
    }
    let expected = u16::from_be_bytes([report[5], report[6]]) as usize;
    tracing::trace!(expected, "Received response length from device");
    if expected > ApduBuffer::CAPACITY {
        return Err(NativeTransportError::ResponseTooLong(expected).into());
    }

    // Only the bytes the device sent are payload. The rest of the report
    // array is stale.
    let mut payload = &report[7..n];
    let mut sequence_idx = 1;
    loop {
        let take = payload.len().min(expected - answer.len());
        answer
            .extend_from_slice(&payload[..take])
            .expect("expected fits in an ApduBuffer");
        if answer.len() == expected {
            return Ok(answer);
        }
        let n = read_report(&mut source, &mut report, channel, sequence_idx)?;
        payload = &report[5..n];
        if payload.is_empty() {
            return Err(NativeTransportError::EmptyReport.into());
        }
        sequence_idx += 1;
    }
}

/// Read a response APDU from the device, waiting up to `timeout` for each
/// report.
fn read_apdu(
    device: &HidDevice,
    channel: u16,
    timeout: Option<Duration>,
) -> Result<ApduBuffer, LedgerError> {
    let timeout_ms = hid_timeout_ms(timeout);
    depacketize(channel, |report| -> Result<usize, LedgerError> {
        let n = device
            .read_timeout(report, timeout_ms)
            .map_err(NativeTransportError::Hid)?;
        // hidapi returns 0 only on timeout, which a blocking read rules out.
        match (n, timeout) {
            (0, Some(timeout)) => Err(LedgerError::Timeout(timeout)),
            _ => Ok(n),
        }
    })
}

/// Send `command` on `device` and read the reply, waiting up to `timeout`
/// for each report. A non-success status word is an error.
pub(super) fn exchange(
    device: &HidDevice,
    command: &ApduCommand,
    timeout: Option<Duration>,
) -> Result<ApduAnswer, LedgerError> {
    write_apdu(device, LEDGER_CHANNEL, command.as_bytes())?;
    let answer = read_apdu(device, LEDGER_CHANNEL, timeout)?;
    ApduAnswer::from_answer(answer)?.into_result()
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
