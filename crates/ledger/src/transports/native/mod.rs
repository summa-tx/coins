//! APDU Transport for native HID.
//!
//! This module contains [`HidTransport`], the main USB access point for ledger
//! devices. [`HidTransport`] implements [`LedgerTransport`] over hid by
//! spawning a background thread managing a [`HidLedgerDevice`].

use crate::{
    ApduAnswer, ApduCommand, LedgerError,
    transports::{DeviceIdentity, LedgerTransport},
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

mod error;
pub use error::NativeTransportError;

mod device;
pub mod hid;
pub use hid::{HidDeviceId, HidLedgerDevice};
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

/// A handle to the Ledger device. This represents exclusive device access.
/// Dropping the handle closes the device once in-flight communications are
/// completed.
///
/// This transport implements [`LedgerTransport`] timeouts on a per-packet
/// basis. I.e. it will wait up to `timeout` for each roundtrip with the device.
/// The timeout is thus the MAXIMUM duration that a user has to push buttons on
/// the device. After a timeout, the next exchange first drops the rest of the
/// late reply. After a report breaks framing, the transport closes the device
/// and later exchanges fail with [`NativeTransportError::IoThreadUnavailable`];
/// reopen it. See [`HidLedgerDevice#timeouts`].
///
/// Generally instantiated via [`HidTransport::open_first`], but
/// [`HidTransport::list`] allows scanning for [`HidDeviceId`]s that can be
/// passed to [`HidTransport::open`].
#[derive(Debug)]
pub struct HidTransport {
    io: IoThread,
    identity: HidDeviceId,
}

impl HidTransport {
    /// List available Ledger devices. Empty under Termux; see
    /// [`HidLedgerDevice::list`].
    pub fn list() -> Result<Vec<HidDeviceId>, NativeTransportError> {
        HidLedgerDevice::list()
    }

    /// Open `id` and spawn its I/O thread. See [`HidLedgerDevice::open`].
    pub fn open(id: &HidDeviceId) -> Result<Self, NativeTransportError> {
        HidLedgerDevice::open(id).map(Self::from_transport)
    }

    /// Open the first Ledger found, or the device Termux hands over, and
    /// spawn its I/O thread. See [`HidLedgerDevice::open_first`].
    pub fn open_first() -> Result<Self, NativeTransportError> {
        HidLedgerDevice::open_first().map(Self::from_transport)
    }

    /// Make a [`HidTransport`] from an open device. This spawns a background
    /// thread that manages device communication.
    ///
    /// # Panics
    ///
    /// If the I/O thread cannot be spawned.
    pub fn from_transport(device: HidLedgerDevice) -> Self {
        let identity = device.id().clone();
        let io = IoActor::spawn(device);
        Self { io, identity }
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

impl LedgerTransport for HidTransport {
    fn identity(&self) -> Option<DeviceIdentity<'_>> {
        Some(DeviceIdentity {
            model: self.identity.model(),
            serial_number: self.identity.serial_number(),
        })
    }

    async fn exchange(
        &mut self,
        command: ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        Span::current().record("device", display(&self.identity));
        self.io.submit(command, timeout).await
    }
}
