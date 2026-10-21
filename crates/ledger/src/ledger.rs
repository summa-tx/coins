use std::time::Duration;

use tracing::debug;

use crate::{
    ApduAnswer, ApduCommand, LedgerError,
    transports::{DeviceId, HidLedger, LedgerTransport},
};

/// A Ledger device connection over a [`LedgerTransport`] (defaulting to
/// [`HidLedger`]).
///
/// Instantiate via:
///
/// - [`Ledger::open_first_hid`] opens the first Ledger found via HID.
/// - [`Ledger::open_hid`] opens one device from [`HidLedger::list`].
/// - [`Ledger::from_transport`] wraps an existing [`HidLedger`], or any
///   [`LedgerTransport`].
#[derive(Debug)]
pub struct Ledger<T = HidLedger> {
    transport: T,
    timeout: Option<Duration>,
}

impl<T> Ledger<T> {
    /// Create a ledger from a transport.
    pub const fn from_transport(transport: T) -> Self {
        Self {
            transport,
            timeout: None,
        }
    }

    /// Set the device read timeout. `None` waits indefinitely.
    pub const fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout
    }

    /// Set the device read timeout. `None` waits indefinitely.
    pub const fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// The device read timeout. `None` waits indefinitely.
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
    /// Open the first Ledger found via HID. See [`HidLedger::open_first`].
    pub fn open_first_hid() -> Result<Self, LedgerError> {
        HidLedger::open_first().map(Self::from_transport)
    }

    /// Open one Ledger via HID. See [`HidLedger::open`].
    pub fn open_hid(id: &DeviceId) -> Result<Self, LedgerError> {
        HidLedger::open(id).map(Self::from_transport)
    }
}

#[cfg(test)]
#[path = "../ai-tests/ledger.rs"]
mod ai_tests;
