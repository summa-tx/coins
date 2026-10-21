use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::{ApduAnswer, ApduCommand, LedgerError, transports::LedgerTransport};

mod error;
pub use error::NativeTransportError;

pub mod hid;
use hid::TransportNativeHID;

/// A packet exchange request.
struct ApduExchange {
    command: ApduCommand,
    /// The per-report read timeout. `None` waits indefinitely.
    timeout: Option<Duration>,
    /// The channel to send the answer back on.
    answer: oneshot::Sender<Result<ApduAnswer, LedgerError>>,
}

/// A handle to the Ledger device. This handle is not clone, as it is critical
/// that only one connection to the device is active at a time. APDUs may NOT
/// be interleaved.
///
/// Dropping the handle closes the device once the I/O thread notices, which
/// is after any exchange in flight completes. On macOS, where opens are
/// exclusive, reopening the device right after a drop can fail.
#[derive(Debug)]
pub struct LedgerHandle {
    tx: mpsc::Sender<ApduExchange>,
}

impl LedgerHandle {
    /// Open the first Ledger found and spawn its I/O thread.
    pub fn init() -> Result<Self, LedgerError> {
        Ok(Self::new(TransportNativeHID::new()?))
    }

    /// Spawn an I/O thread for a device you opened yourself, e.g. one of
    /// [`TransportNativeHID::open_all_devices`].
    pub fn new(mut device: TransportNativeHID) -> Self {
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

impl LedgerTransport for LedgerHandle {
    /// Exchange a packet, waiting up to `timeout` for each report of the
    /// reply. `None` waits indefinitely. Durations over `i32::MAX` ms are
    /// clamped.
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
