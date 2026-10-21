use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::{ApduAnswer, ApduCommand, LedgerError, transports::LedgerTransport};

mod error;
pub use error::NativeTransportError;

pub mod hid;
use hid::TransportNativeHID;

/// A packet exchange request.
struct ApduExchange {
    /// The command to send to the device.
    command: ApduCommand,
    /// The channel to send the answer back on.
    answer: oneshot::Sender<Result<ApduAnswer, LedgerError>>,
    /// The per-report read timeout. `None` waits indefinitely.
    timeout: Option<Duration>,
}

impl ApduExchange {
    /// Create a new exchange request.
    fn new(
        command: ApduCommand,
        timeout: Option<Duration>,
    ) -> (Self, oneshot::Receiver<Result<ApduAnswer, LedgerError>>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                command,
                answer: tx,
                timeout,
            },
            rx,
        )
    }
}

/// A task that manages Ledger packet exchange.
struct LedgerTask {
    ledger: TransportNativeHID,
    rx: tokio::sync::mpsc::Receiver<ApduExchange>,
}

impl LedgerTask {
    /// Create a new task.
    fn new(ledger: TransportNativeHID) -> (Self, tokio::sync::mpsc::Sender<ApduExchange>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        (Self { ledger, rx }, tx)
    }

    /// Spawn the thread that performs the device I/O.
    fn spawn(mut self) {
        std::thread::spawn(move || {
            while let Some(exchange) = self.rx.blocking_recv() {
                // blocking IO
                let answer = self.ledger.exchange(&exchange.command, exchange.timeout);

                if exchange.answer.send(answer).is_err() {
                    tracing::debug!("exchange was dropped before its answer arrived");
                }
            }
        });
    }
}

/// A handle to the Ledger device. This handle is not clone, as it is critical
/// that only one connection to the device is active at a time. APDUs may NOT
/// be interleaved.
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
    pub fn new(transport: TransportNativeHID) -> Self {
        let (task, tx) = LedgerTask::new(transport);
        task.spawn();
        Self { tx }
    }
}

impl From<TransportNativeHID> for LedgerHandle {
    fn from(transport: TransportNativeHID) -> Self {
        Self::new(transport)
    }
}

impl LedgerTransport for LedgerHandle {
    /// Exchange a packet, waiting up to `timeout` for each report of the
    /// reply. `None` waits indefinitely. Durations over `i32::MAX` ms are
    /// clamped.
    async fn exchange(
        &mut self,
        apdu: ApduCommand,
        timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        let (exchange, rx) = ApduExchange::new(apdu, timeout);
        self.tx.send(exchange).await?;
        rx.await?
    }
}
