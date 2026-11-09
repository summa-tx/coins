//! Ledger discovery over native HID.

use std::{
    ffi::{CStr, CString},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{
        LazyLock,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
};

use hidapi::{DeviceInfo, HidApi};
use tracing::{Span, debug, error};

use super::device::HidLedgerDevice;
use crate::{Model, transports::native::error::NativeTransportError};

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;

/// The HID context thread. See [`HidThread`].
static HID_THREAD: LazyLock<HidThread> = LazyLock::new(HidThread::spawn);

/// A reply to a [`HidJob`]: its output, or the panic it raised.
type Reply<T> = SyncSender<thread::Result<Result<T, NativeTransportError>>>;

/// A connected Ledger's APDU interface, as [`HidTransport::list`]
/// found it. Opens the device via [`HidTransport::open`]. Valid until
/// the device is unplugged; the path is reassigned on the next plug-in.
///
/// [`HidTransport::list`]: super::HidTransport::list
/// [`HidTransport::open`]: super::HidTransport::open
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

    /// The platform HID path, which may change on each plug-in. On Linux
    /// this is the `/dev/hidraw*` node; elsewhere it is opaque.
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

/// A hidapi context call, carrying the channel its output goes back on.
#[derive(Debug)]
pub(super) enum HidJob {
    /// See [`HidLedgerDevice::list`].
    List { reply: Reply<Vec<HidDeviceId>> },
    /// See [`HidLedgerDevice::open`].
    Open {
        id: HidDeviceId,
        reply: Reply<HidLedgerDevice>,
    },
    /// See [`HidLedgerDevice::open_first`].
    OpenFirst { reply: Reply<HidLedgerDevice> },
}

/// A request to the [`HidActor`].
#[derive(Debug)]
struct HidRequest {
    job: HidJob,
    /// A tracing span associated with the request. Used to propagate trace
    /// info to the HID thread.
    span: Span,
}

/// A handle to the thread that runs every hidapi context call. There is one,
/// started on first use and kept for the life of the process; get it with
/// [`HidThread::get`].
///
/// hidapi's macOS backend schedules its global device manager on the run
/// loop of the thread that first initializes it, and holds that run loop
/// unretained. If the thread exits while another thread is enumerating, the
/// run loop is freed mid-enumeration and the process traps. Keeping one
/// thread alive for the life of the process, and doing every context call
/// there, avoids that. Device I/O does not touch the manager and stays on
/// the caller's thread.
#[derive(Debug)]
pub(super) struct HidThread {
    tx: SyncSender<HidRequest>,
}

impl HidThread {
    /// The HID context thread, spawned on first use.
    ///
    /// # Panics
    ///
    /// If the thread cannot be spawned.
    pub(super) fn get() -> &'static Self {
        &HID_THREAD
    }

    /// Spawn the HID context thread and return its handle. Requests travel
    /// by value over a rendezvous channel, and each carries its own reply
    /// channel. The thread handles requests until every handle is dropped.
    ///
    /// If hidapi fails to initialize, the error is logged and the thread
    /// exits, so every request fails as
    /// [`NativeTransportError::HidThreadUnavailable`].
    ///
    /// # Panics
    ///
    /// If the thread cannot be spawned.
    fn spawn() -> HidThread {
        let (tx, rx) = sync_channel(0);
        thread::Builder::new()
            .name("coins-ledger-hid".into())
            .spawn(move || {
                let mut actor = match HidActor::boot(rx) {
                    Ok(actor) => actor,
                    Err(err) => {
                        error!(%err, "failed to initialize hidapi");
                        return;
                    }
                };
                while let Ok(request) = actor.rx.recv() {
                    actor.handle(request);
                }
            })
            .expect("failed to spawn the HID context thread");
        Self { tx }
    }

    /// Build a job around a fresh reply channel, run it on this thread
    /// inside the caller's current span, and wait for its output. A panic in
    /// the job is propagated to the caller.
    pub(super) fn submit<T>(
        &self,
        job: impl FnOnce(Reply<T>) -> HidJob,
    ) -> Result<T, NativeTransportError> {
        let (reply, output) = sync_channel(1);
        self.tx
            .send(HidRequest {
                job: job(reply),
                span: Span::current(),
            })
            .map_err(|_| NativeTransportError::HidThreadUnavailable)?;
        match output.recv() {
            Ok(Ok(output)) => output,
            Ok(Err(panic)) => resume_unwind(panic),
            Err(_) => Err(NativeTransportError::HidThreadUnavailable),
        }
    }
}

/// The state of the HID context thread. Started by [`HidThread::spawn`];
/// reached through a [`HidThread`].
///
/// Unlike a device's I/O thread, this thread must outlive any one call, so a
/// panic in a job is caught and sent back to the caller rather than ending
/// the thread.
struct HidActor {
    rx: Receiver<HidRequest>,
    api: HidApi,
}

impl HidActor {
    /// Initialize the hidapi context. Runs on the HID context thread.
    fn boot(rx: Receiver<HidRequest>) -> Result<Self, NativeTransportError> {
        // Termux cannot enumerate, and discovery can only be disabled before
        // the context is created.
        #[cfg(target_os = "android")]
        if HidLedgerDevice::is_termux() {
            HidApi::disable_device_discovery();
        }
        Ok(Self {
            rx,
            api: HidApi::new()?,
        })
    }

    /// Run one request's job inside its span and send back the output.
    fn handle(&mut self, HidRequest { job, span }: HidRequest) {
        let _entered = span.entered();
        match job {
            HidJob::List { reply } => respond(reply, || self.list()),
            HidJob::Open { id, reply } => respond(reply, || self.open(id)),
            HidJob::OpenFirst { reply } => respond(reply, || self.open_first()),
        }
    }

    /// The context, with its device list refreshed to the attached Ledger
    /// devices.
    fn enumerate(&mut self) -> Result<&HidApi, NativeTransportError> {
        self.api.reset_devices()?;
        self.api.add_devices(LEDGER_VID, 0)?;
        Ok(&self.api)
    }

    /// The Ledger APDU interfaces currently attached.
    fn list(&mut self) -> Result<Vec<HidDeviceId>, NativeTransportError> {
        Ok(HidDeviceId::ledgers(self.enumerate()?)
            .map(HidDeviceId::from_info)
            .collect())
    }

    /// Open the device at `id`. Opening by path needs no enumeration.
    fn open(&mut self, id: HidDeviceId) -> Result<HidLedgerDevice, NativeTransportError> {
        let device = self
            .api
            .open_path(&id.path)
            .map_err(NativeTransportError::CantOpen)?;
        Ok(HidLedgerDevice::new(device, id))
    }

    /// Open the first Ledger found, or the device Termux hands over.
    fn open_first(&mut self) -> Result<HidLedgerDevice, NativeTransportError> {
        #[cfg(target_os = "android")]
        if let Some(device) = HidLedgerDevice::open_termux(&self.api)? {
            return Ok(device);
        }

        let api = self.enumerate()?;
        let info = HidDeviceId::ledgers(api)
            .next()
            .ok_or(NativeTransportError::DeviceNotFound)?;
        let device = info
            .open_device(api)
            .map_err(NativeTransportError::CantOpen)?;
        Ok(HidLedgerDevice::new(device, HidDeviceId::from_info(info)))
    }
}

/// Run `f` and send its output, or its panic, back on `reply`.
fn respond<T>(reply: Reply<T>, f: impl FnOnce() -> Result<T, NativeTransportError>) {
    if reply.send(catch_unwind(AssertUnwindSafe(f))).is_err() {
        debug!("HID request was dropped before its reply arrived");
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
