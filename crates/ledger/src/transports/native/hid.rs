//! Ledger discovery over native HID, and the thread that runs every hidapi
//! context call.
//!
//! Every hidapi context call runs on one thread that lives as long as the
//! process; `HidThread` explains why. An application that mixes HID
//! crates should likewise initialize hidapi once from a long-lived thread,
//! because whichever crate initializes first decides where hidapi's device
//! manager lives.

use std::{
    ffi::{CStr, CString},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{
        LazyLock, Mutex, PoisonError,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
};

use hidapi::{DeviceInfo, HidApi};
use tracing::Span;

pub use super::device::HidLedgerDevice;
use crate::{Model, transports::native::error::NativeTransportError};

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;

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
    /// True if a HID interface is the APDU interface of a Ledger device.
    ///
    /// The usage page identifies it wherever hidapi reports one. On Linux,
    /// older hidapi builds report no usage page, so interface 0 is accepted as
    /// well. This mirrors the filter in Ledger's own transports. The FIDO
    /// interface a device exposes alongside is rejected either way.
    const fn is_ledger_interface(vendor_id: u16, usage_page: u16, interface_number: i32) -> bool {
        let apdu_interface =
            usage_page == LEDGER_USAGE_PAGE || (cfg!(target_os = "linux") && interface_number == 0);
        vendor_id == LEDGER_VID && apdu_interface
    }

    /// The Ledger APDU interfaces in `api`'s device list.
    fn ledgers(api: &HidApi) -> impl Iterator<Item = &DeviceInfo> {
        api.device_list().filter(|dev| {
            Self::is_ledger_interface(dev.vendor_id(), dev.usage_page(), dev.interface_number())
        })
    }

    pub(super) fn from_info(info: &DeviceInfo) -> Self {
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

/// A hidapi context call.
#[derive(Debug)]
pub(super) enum HidJob {
    /// See [`HidLedgerDevice::list`].
    List,
    /// See [`HidLedgerDevice::open`].
    Open(HidDeviceId),
    /// See [`HidLedgerDevice::open_first`].
    OpenFirst,
}

/// What a [`HidJob`] yields.
#[derive(Debug)]
pub(super) enum HidOutput {
    List(Vec<HidDeviceId>),
    Device(HidLedgerDevice),
}

impl HidOutput {
    pub(super) fn into_ids(self) -> Vec<HidDeviceId> {
        match self {
            Self::List(ids) => ids,
            Self::Device(_) => unreachable!("listing yields IDs"),
        }
    }

    pub(super) fn into_device(self) -> HidLedgerDevice {
        match self {
            Self::Device(device) => device,
            Self::List(_) => unreachable!("opening yields a device"),
        }
    }
}

impl HidJob {
    /// Run this job on [`HID_THREAD`].
    pub(super) fn submit(self) -> Result<HidOutput, NativeTransportError> {
        HID_THREAD
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .run(self)
    }

    fn run(self) -> Result<HidOutput, NativeTransportError> {
        match self {
            Self::List => {
                let api = HidApi::new()?;
                let ids = HidDeviceId::ledgers(&api)
                    .map(HidDeviceId::from_info)
                    .collect();
                Ok(HidOutput::List(ids))
            }
            Self::Open(id) => {
                let device = HidApi::new()?
                    .open_path(&id.path)
                    .map_err(NativeTransportError::CantOpen)?;
                Ok(HidOutput::Device(HidLedgerDevice::new(device, id)))
            }
            Self::OpenFirst => {
                #[cfg(target_os = "android")]
                if let Some(device) = HidLedgerDevice::open_termux()? {
                    return Ok(HidOutput::Device(device));
                }

                let api = HidApi::new()?;
                let info = HidDeviceId::ledgers(&api)
                    .next()
                    .ok_or(NativeTransportError::DeviceNotFound)?;
                let device = info
                    .open_device(&api)
                    .map_err(NativeTransportError::CantOpen)?;
                let id = HidDeviceId::from_info(info);
                Ok(HidOutput::Device(HidLedgerDevice::new(device, id)))
            }
        }
    }
}

/// The thread that runs every hidapi context call. There is one, in
/// [`HID_THREAD`], started on first use and kept for the life of the process.
/// Jobs and their outputs travel by value over rendezvous channels.
///
/// hidapi's macOS backend schedules its global device manager on the run
/// loop of the thread that first initializes it, and holds that run loop
/// unretained. If the thread exits while another thread is enumerating, the
/// run loop is freed mid-enumeration and the process traps. Keeping one
/// thread alive for the life of the process, and doing every context call
/// there, avoids that. Device I/O does not touch the manager and stays on
/// the caller's thread.
#[derive(Debug)]
struct HidThread {
    jobs: SyncSender<(HidJob, Span)>,
    outputs: Receiver<thread::Result<Result<HidOutput, NativeTransportError>>>,
}

/// The process's HID context thread. Holding the lock across a round trip
/// keeps one job in flight, so each output reaches the caller whose job it is.
static HID_THREAD: LazyLock<Mutex<HidThread>> = LazyLock::new(|| Mutex::new(HidThread::spawn()));

impl HidThread {
    /// Run `job` on the thread, inside the caller's current span, and wait
    /// for its output. A panic in the job is propagated to the caller.
    fn run(&mut self, job: HidJob) -> Result<HidOutput, NativeTransportError> {
        self.jobs
            .send((job, Span::current()))
            .map_err(|_| NativeTransportError::HidThreadUnavailable)?;
        match self.outputs.recv() {
            Ok(Ok(output)) => output,
            Ok(Err(panic)) => resume_unwind(panic),
            Err(_) => Err(NativeTransportError::HidThreadUnavailable),
        }
    }

    /// # Panics
    ///
    /// If the thread cannot be spawned.
    fn spawn() -> Self {
        let (jobs, job_rx) = sync_channel::<(HidJob, Span)>(0);
        let (output_tx, outputs) = sync_channel(0);
        thread::Builder::new()
            .name("coins-ledger-hid".into())
            .spawn(move || {
                for (job, span) in job_rx {
                    let output = catch_unwind(AssertUnwindSafe(|| span.in_scope(|| job.run())));
                    if output_tx.send(output).is_err() {
                        break;
                    }
                }
            })
            .expect("failed to spawn the HID context thread");
        Self { jobs, outputs }
    }
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
