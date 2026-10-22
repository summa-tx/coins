use std::time::Duration;

#[cfg(feature = "speculos")]
use tokio::net::ToSocketAddrs;
use tracing::{Level, Span, debug, enabled, instrument};

use crate::{
    ApduAnswer, ApduCommand, LedgerError,
    transports::{
        DeviceIdentity, HidDeviceId, HidTransport, LedgerTransport, NativeTransportError,
    },
};
#[cfg(feature = "speculos")]
use crate::{
    Model,
    transports::{SpeculosError, SpeculosTransport},
};

/// A Ledger device connection over a [`LedgerTransport`] (defaulting to
/// [`HidTransport`]).
///
/// Instantiate via:
///
/// - [`Ledger::open_first_hid`] opens the first Ledger found via HID.
/// - [`Ledger::open_hid`] opens one device from [`Ledger::list_hid`].
/// - [`Ledger::connect_speculos`] connects to a Speculos emulator (with the
///   `speculos` feature).
/// - [`Ledger::from_transport`] wraps an existing [`HidTransport`], or any
///   [`LedgerTransport`].
#[derive(Debug)]
pub struct Ledger<T = HidTransport> {
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

    /// The underlying transport, for transport-specific operations such as
    /// recovering from a failed exchange.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T> Ledger<T>
where
    T: LedgerTransport,
{
    /// The device this ledger talks to, if the transport knows.
    pub fn identity(&self) -> Option<DeviceIdentity<'_>> {
        self.transport.identity()
    }

    /// Exchange a packet with the device, waiting up to the configured
    /// timeout for each report of the reply.
    #[instrument(
        level = "debug",
        skip_all,
        fields(
            device,
            cla = packet.cla(),
            ins = packet.ins(),
            p1 = packet.p1(),
            p2 = packet.p2(),
            len = packet.data().len(),
            data,
            response,
        )
    )]
    pub async fn exchange(&mut self, packet: ApduCommand) -> Result<ApduAnswer, LedgerError> {
        // NB: if trace is enabled, the span above is enabled, and `current` is
        // the expected span.
        if enabled!(Level::TRACE) {
            Span::current().record("data", hex::encode(packet.data()));
        }

        self.transport
            .exchange(packet, self.timeout)
            .await
            .inspect(|resp| {
                if enabled!(Level::TRACE) {
                    Span::current().record("response", hex::encode(resp.data()));
                }
                debug!(
                    status = %resp.status(),
                    len = resp.data().len(),
                    "Received response from device"
                )
            })
            .inspect_err(|err| debug!(%err, "Exchange failed"))
    }
}

impl Ledger {
    /// Open the first Ledger found via HID. See [`HidTransport::open_first`].
    pub fn open_first_hid() -> Result<Self, NativeTransportError> {
        HidTransport::open_first().map(Self::from_transport)
    }

    /// Open a Ledger via HID. See [`HidTransport::open`].
    pub fn open_hid(id: &HidDeviceId) -> Result<Self, NativeTransportError> {
        HidTransport::open(id).map(Self::from_transport)
    }

    /// List available Ledger HID devices. See [`HidTransport::list`]
    pub fn list_hid() -> Result<Vec<HidDeviceId>, NativeTransportError> {
        HidTransport::list()
    }
}

#[cfg(feature = "speculos")]
#[cfg_attr(docsrs, doc(cfg(feature = "speculos")))]
impl Ledger<SpeculosTransport> {
    /// Connect to the APDU socket of a Speculos instance emulating `model`.
    /// See [`SpeculosTransport::connect`].
    ///
    /// After an exchange times out or is cancelled, the transport refuses
    /// further exchanges until its reply is consumed. Resolve the prompt on
    /// screen, then call
    /// [`ledger.transport_mut().discard_pending(..)`](SpeculosTransport::discard_pending).
    pub async fn connect_speculos(
        addr: impl ToSocketAddrs,
        model: Model,
    ) -> Result<Self, SpeculosError> {
        SpeculosTransport::connect(addr, model)
            .await
            .map(Self::from_transport)
    }
}

#[cfg(test)]
#[path = "../ai-tests/ledger.rs"]
mod ai_tests;
