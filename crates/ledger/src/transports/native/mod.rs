//! APDU Transport for native HID.
//!
//! This module contains [`HidTransport`], the main USB access point for ledger
//! devices. [`HidTransport`] implements [`LedgerTransport`].

use crate::{
    ApduAnswer, ApduCommand, LedgerError,
    transports::{DeviceIdentity, LedgerTransport},
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

mod error;
pub use error::NativeTransportError;

mod device;
#[cfg(feature = "sync-hid")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync-hid")))]
pub use device::HidLedgerDevice;
#[cfg(not(feature = "sync-hid"))]
use device::HidLedgerDevice;

mod hid;
pub use hid::HidDeviceId;

mod report;

use tracing::{Span, debug, field::display};

/// A request to an [`IoActor`].
struct ApduExchange {
    command: ApduCommand,
    /// The per-report read timeout. `None` waits indefinitely.
    timeout: Option<Duration>,
    /// The channel to send the answer back on.
    answer: oneshot::Sender<Result<ApduAnswer, LedgerError>>,
    /// A tracing span associated with the exchange. Used to propagate trace
    /// info to the I/O thread.
    span: Span,
}

/// A handle to the Ledger device. Dropping the handle closes the device once
/// in-flight communications are completed. See
/// [Exclusive access](#exclusive-access) for whether other clients can use
/// the device meanwhile.
///
/// This transport implements [`LedgerTransport`] timeouts per packet: it
/// waits up to `timeout` for each roundtrip with the device, so the timeout
/// is the most time a user has to press buttons. After a timeout, the next
/// exchange may also time out while the device finishes the earlier reply.
/// If the device sends a reply that cannot be read, the transport closes and
/// later exchanges fail with [`NativeTransportError::IoThreadUnavailable`];
/// reopen it.
///
/// Generally instantiated via [`HidTransport::open_first`], but
/// [`HidTransport::list`] allows scanning for [`HidDeviceId`]s that can be
/// passed to [`HidTransport::open`].
#[cfg_attr(
    feature = "sync-hid",
    doc = "\nFor blocking exchanges on the caller's thread, use [`HidLedgerDevice`]."
)]
#[cfg_attr(
    not(feature = "sync-hid"),
    doc = "\nFor blocking exchanges on the caller's thread, use `HidLedgerDevice`\n(with the `sync-hid` feature)."
)]
///
/// # Exclusive access
///
/// Another client of the same Ledger, such as Ledger Live or a browser
/// using WebHID, can consume replies meant for this handle. Whether an open
/// keeps other clients out depends on the platform:
///
/// - **macOS** and **Android (Termux)**: exclusive. The open fails while
///   another client holds the device, and keeps others out until this
///   handle is dropped.
/// - **Linux**: shared. To check for other clients, run `fuser -v` on the
///   `/dev/hidraw*` node from [`HidTransport::id`] and
///   [`HidDeviceId::path`]. Nothing enforces exclusivity: a udev rule can
///   restrict the node to one user, but that user's other processes can
///   still open it. Quit other Ledger clients first.
/// - **Windows**: shared. To check for other clients, search for the
///   device's [path](HidDeviceId::path) in Sysinternals Handle or Process
///   Explorer.
///   Nothing enforces exclusivity. Quit other Ledger clients first.
///
/// Where opens are shared, two handles to one device in the same process
/// are allowed too, and their exchanges interleave.
#[derive(Debug)]
pub struct HidTransport {
    io: IoThread,
    id: HidDeviceId,
}

impl HidTransport {
    /// Every Ledger APDU interface attached right now. Enumerates afresh on
    /// each call.
    ///
    /// On Android under Termux, which cannot enumerate USB devices, this is
    /// empty. Use [`HidTransport::open_first`], which takes the device Termux
    /// hands over.
    ///
    /// # Panics
    ///
    /// On first use, if a background thread cannot be spawned.
    pub fn list() -> Result<Vec<HidDeviceId>, NativeTransportError> {
        HidLedgerDevice::list()
    }

    /// Open `id`. Fails as [`NativeTransportError::CantOpen`] if the device
    /// was unplugged, or another client holds it where opens are
    /// [exclusive](HidTransport#exclusive-access).
    ///
    /// # Panics
    ///
    /// If a background thread cannot be spawned.
    pub fn open(id: &HidDeviceId) -> Result<Self, NativeTransportError> {
        HidLedgerDevice::open(id).map(Self::from_device)
    }

    /// Open the first Ledger found. Devices are enumerated afresh on every
    /// call. On Android under Termux, which cannot enumerate, this opens the
    /// device `termux-usb` hands over instead.
    ///
    /// Where opens are [exclusive](HidTransport#exclusive-access), this fails
    /// while another client, or another handle in this process, holds it.
    ///
    /// # Panics
    ///
    /// If a background thread cannot be spawned.
    pub fn open_first() -> Result<Self, NativeTransportError> {
        HidLedgerDevice::open_first().map(Self::from_device)
    }

    /// The device this transport opened.
    pub const fn id(&self) -> &HidDeviceId {
        &self.id
    }

    /// Make a [`HidTransport`] from an open device.
    ///
    /// # Panics
    ///
    /// If a background thread cannot be spawned.
    fn from_device(device: HidLedgerDevice) -> Self {
        let id = device.id().clone();
        let io = IoActor::spawn(device);
        Self { io, id }
    }
}

impl LedgerTransport for HidTransport {
    fn identity(&self) -> Option<DeviceIdentity<'_>> {
        Some(DeviceIdentity {
            model: self.id.model(),
            serial_number: self.id.serial_number(),
        })
    }

    async fn exchange(
        &mut self,
        command: ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        Span::current().record("device", display(&self.id));
        self.io.submit(command, timeout).await
    }
}

/// A handle to the thread that drives one device's blocking I/O, one
/// exchange at a time. The thread ends, dropping the device, when the handle
/// is dropped or after a framing error. Made by [`IoActor::spawn`].
#[derive(Debug)]
struct IoThread {
    tx: mpsc::Sender<ApduExchange>,
}

impl IoThread {
    /// Run `command` on this thread inside the caller's current span, and
    /// wait for its answer.
    async fn submit(
        &self,
        command: ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        let (answer, rx) = oneshot::channel();
        self.tx
            .send(ApduExchange {
                command,
                timeout,
                answer,
                span: Span::current(),
            })
            .await
            .map_err(|_| NativeTransportError::IoThreadUnavailable)?;
        rx.await
            .map_err(|_| NativeTransportError::IoThreadUnavailable)?
    }
}

/// The state of one device's I/O thread: the device it drives. Started by
/// [`IoActor::spawn`]; reached through an [`IoThread`].
struct IoActor {
    rx: mpsc::Receiver<ApduExchange>,
    device: HidLedgerDevice,
}

impl IoActor {
    /// Spawn the I/O thread for `device` and return its handle.
    ///
    /// # Panics
    ///
    /// If the thread cannot be spawned.
    fn spawn(device: HidLedgerDevice) -> IoThread {
        let (tx, rx) = mpsc::channel(1);
        std::thread::Builder::new()
            .name("coins-ledger-io".into())
            .spawn(move || {
                let mut actor = Self { rx, device };
                while let Some(exchange) = actor.rx.blocking_recv() {
                    actor.handle(exchange);
                    // What the device owes is unknown, so a later reply could
                    // be misread. Close it.
                    if actor.device.is_broken() {
                        debug!("closing the device after a framing error");
                        break;
                    }
                }
            })
            .expect("failed to spawn the Ledger I/O thread");
        IoThread { tx }
    }

    /// Run one exchange inside its span and send back the answer.
    fn handle(
        &mut self,
        ApduExchange {
            command,
            timeout,
            answer,
            span,
        }: ApduExchange,
    ) {
        let _entered = span.entered();
        if answer
            .send(self.device.exchange(&command, timeout))
            .is_err()
        {
            debug!("exchange was dropped before its answer arrived");
        }
    }
}
