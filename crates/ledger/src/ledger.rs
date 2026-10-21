use std::time::Duration;

use tracing::debug;

use crate::{
    ApduAnswer, ApduCommand, LedgerError,
    transports::{LedgerHandle, LedgerTransport},
};

/// A Ledger device connection over a [`LedgerTransport`]. The default is the
/// native HID handle.
///
/// Three ways to get one:
///
/// - [`Ledger::new`] opens the first Ledger found.
/// - [`LedgerHandle::new`] wraps a device you opened yourself, e.g. one of
///   [`TransportNativeHID::open_all_devices`](crate::transports::native::hid::TransportNativeHID::open_all_devices),
///   and [`Ledger::from_handle`] takes it from there.
/// - [`Ledger::from_handle`] also takes any [`LedgerTransport`] of your own,
///   such as a connection to an emulator:
///
/// ```
/// use std::time::Duration;
///
/// use coins_ledger::{
///     ApduAnswer, ApduBuffer, ApduCommand, Ledger, LedgerError, transports::LedgerTransport,
/// };
///
/// /// Answers every command with success and no data.
/// struct Stub;
///
/// impl LedgerTransport for Stub {
///     async fn exchange(
///         &mut self,
///         _command: ApduCommand,
///         _timeout: Option<Duration>,
///     ) -> Result<ApduAnswer, LedgerError> {
///         let mut reply = ApduBuffer::new();
///         reply.extend_from_slice(&[0x90, 0x00]).unwrap();
///         ApduAnswer::from_answer(reply)?.into_result()
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let mut ledger = Ledger::from_handle(Stub);
/// let version = ApduCommand::builder().cla(0xe0).ins(0x06).build()?;
/// assert!(ledger.exchange(version).await?.is_success());
/// # Ok::<(), LedgerError>(())
/// # }).unwrap();
/// ```
#[derive(Debug)]
pub struct Ledger<T = LedgerHandle> {
    transport: T,
    timeout: Option<Duration>,
}

impl<T> Ledger<T> {
    /// Create a ledger from a handle. Starts with no timeout: the device may
    /// be waiting on the user, which takes as long as it takes.
    pub const fn from_handle(transport: T) -> Self {
        Self {
            transport,
            timeout: None,
        }
    }

    /// Set the per-report read timeout. `None` waits indefinitely.
    pub const fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout
    }

    /// The per-report read timeout. `None` waits indefinitely.
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

impl<T> Ledger<T>
where
    T: LedgerTransport,
{
    /// Exchange a packet with the device, waiting up to the configured
    /// timeout for each report of the reply.
    pub async fn exchange(&mut self, packet: ApduCommand) -> Result<ApduAnswer, LedgerError> {
        debug!(command = ?packet, "dispatching APDU to device");
        self.transport
            .exchange(packet, self.timeout)
            .await
            .inspect(|resp| {
                debug!(
                    status = %resp.status(),
                    response = hex::encode(resp.data()),
                    "Received response from device"
                )
            })
            .inspect_err(|err| debug!(%err, "Exchange failed"))
    }
}

impl Ledger {
    /// Instantiate a new Ledger using the default transport
    pub fn new() -> Result<Self, LedgerError> {
        LedgerHandle::init().map(Self::from_handle)
    }
}

#[cfg(test)]
#[path = "../ai-tests/ledger.rs"]
mod ai_tests;
