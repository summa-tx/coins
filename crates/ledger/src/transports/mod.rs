//! Abstract ledger transport trait with a native HID instantiation.

use crate::{
    common::{APDUAnswer, APDUCommand},
    errors::LedgerError,
};
use async_trait::async_trait;
use tracing::{debug, error};

/// APDU Transport for native HID. Wraps
/// [`TransportNativeHID`][native::hid::TransportNativeHID] in a
/// thread managing the IO.
pub mod native;
pub use native::LedgerHandle as DefaultTransport;

/// A Ledger device connection. This wraps the default transport type, which
/// is backed by the `hidapi` library.
#[derive(Debug)]
pub struct Ledger(DefaultTransport);

/// An asynchronous interface to the Ledger device. It is critical that the
/// device have only one connection active, so the `init` function acquires a
/// lock on the device.
#[async_trait]
pub trait LedgerAsync: Sized {
    /// Init the connection to the device. This may fail if the device is already in use by some
    /// other process.
    async fn init() -> Result<Self, LedgerError>;

    /// Exchange a packet with the device.
    async fn exchange(&self, packet: &APDUCommand) -> Result<APDUAnswer, LedgerError>;

    /// Consume the connection, and release the resources it holds.
    ///
    /// By default this function simply drops the struct.
    fn close(self) {}
}

#[async_trait]
impl LedgerAsync for Ledger {
    async fn init() -> Result<Self, LedgerError> {
        Ok(Self(DefaultTransport::init()?))
    }

    async fn exchange(&self, packet: &APDUCommand) -> Result<APDUAnswer, LedgerError> {
        debug!(command = %packet, "dispatching APDU to device");

        // TODO: remove clone
        let resp = self.0.exchange(packet.clone()).await;
        match &resp {
            Ok(resp) => {
                debug!(
                    retcode = resp.retcode(),
                    response = resp.data().map(hex::encode),
                    "Received response from device"
                )
            }
            Err(err) => error!(%err, "Error during communication"),
        }
        resp
    }
}

/*******************************************************************************
 *   (c) 2020 ZondaX GmbH
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
