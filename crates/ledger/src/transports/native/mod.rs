use crate::{ApduAnswer, ApduCommand, LedgerError, transports::LedgerTransport};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

mod error;
pub use error::NativeTransportError;

pub mod hid;
pub use hid::DeviceId;
use hid::TransportNativeHID;

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
/// Open the first device found with [`HidLedger::open_first`], or pick one
/// from [`HidLedger::list`] and pass it to [`HidLedger::open`]. Under Termux,
/// which cannot enumerate USB devices, only `open_first` works: it takes the
/// device `termux-usb` hands over.
#[derive(Debug)]
pub struct HidLedger {
    tx: mpsc::Sender<ApduExchange>,
}

impl HidLedger {
    /// Every Ledger attached right now. Empty under Termux; see
    /// [`TransportNativeHID::list`].
    pub fn list() -> Result<Vec<DeviceId>, LedgerError> {
        Ok(TransportNativeHID::list()?)
    }

    /// Open `id` and spawn its I/O thread. See [`TransportNativeHID::open`].
    pub fn open(id: &DeviceId) -> Result<Self, LedgerError> {
        Ok(Self::from_transport(TransportNativeHID::open(id)?))
    }

    /// Open the first Ledger found, or the device Termux hands over, and
    /// spawn its I/O thread. See [`TransportNativeHID::open_first`].
    pub fn open_first() -> Result<Self, LedgerError> {
        Ok(Self::from_transport(TransportNativeHID::open_first()?))
    }

    /// Spawn an I/O thread for a device you opened yourself.
    pub fn from_transport(mut device: TransportNativeHID) -> Self {
        let (tx, mut rx) = mpsc::channel(1);
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

impl LedgerTransport for HidLedger {
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
