//! APDU Transport for native HID.
//!
//! This module contains [`HidTransport`], the main USB access point for ledger
//! devices. [`HidTransport`] implements [`LedgerTransport`] over hid by
//! spawning a background thread managing a [`HidLedgerDevice`].

use crate::{ApduAnswer, ApduCommand, LedgerError, transports::LedgerTransport};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

mod error;
pub use error::NativeTransportError;

pub mod hid;
pub use hid::{DeviceId, HidLedgerDevice};

/// A packet exchange request.
struct ApduExchange {
    command: ApduCommand,
    /// The per-report read timeout. `None` waits indefinitely.
    timeout: Option<Duration>,
    /// The channel to send the answer back on.
    answer: oneshot::Sender<Result<ApduAnswer, LedgerError>>,
}

/// A handle to the Ledger device. This represents exclusive device access.
/// Dropping the handle closes the device once in-flight communications are
/// completed.
///
/// This transport implements [`LedgerTransport`] timeouts on a per-packet
/// basis. I.e. it will wait up to `timeout` for each roundtrip with the device.
/// The timeout is thus the MAXIMUM duration that a user has to push buttons on
/// the device.
///
/// Generally instantiated via [`HidTransport::open_first`], but
/// [`HidTransport::list`] allows scanning for [`DeviceId`]s that can be passed
/// to [`HidTransport::open`].
#[derive(Debug)]
pub struct HidTransport {
    tx: mpsc::Sender<ApduExchange>,
}

impl HidTransport {
    /// List available Ledger devices. Empty under Termux; see
    /// [`HidLedgerDevice::list`].
    pub fn list() -> Result<Vec<DeviceId>, LedgerError> {
        HidLedgerDevice::list().map_err(Into::into)
    }

    /// Open `id` and spawn its I/O thread. See [`HidLedgerDevice::open`].
    pub fn open(id: &DeviceId) -> Result<Self, LedgerError> {
        HidLedgerDevice::open(id)
            .map(Self::from_transport)
            .map_err(Into::into)
    }

    /// Open the first Ledger found, or the device Termux hands over, and
    /// spawn its I/O thread. See [`HidLedgerDevice::open_first`].
    pub fn open_first() -> Result<Self, LedgerError> {
        HidLedgerDevice::open_first()
            .map(Self::from_transport)
            .map_err(Into::into)
    }

    /// Make a [`HidTransport`] from an open device. This spawns a background
    /// thread that manages device communication.
    pub fn from_transport(mut device: HidLedgerDevice) -> Self {
        let (tx, mut rx) = mpsc::channel(1);

        // Spawn a task that drives the blocking transport.
        std::thread::spawn(move || {
            while let Some(ApduExchange {
                command,
                timeout,
                answer,
            }) = rx.blocking_recv()
            {
                if answer.send(device.exchange(&command, timeout)).is_err() {
                    tracing::debug!("exchange was dropped before its answer arrived");
                }
            }
        });
        Self { tx }
    }
}

impl LedgerTransport for HidTransport {
    async fn exchange(
        &mut self,
        command: ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        let (answer, rx) = oneshot::channel();
        self.tx
            .send(ApduExchange {
                command,
                timeout,
                answer,
            })
            .await
            .map_err(|_| LedgerError::BackendGone)?;
        rx.await.map_err(|_| LedgerError::BackendGone)?
    }
}
