//! Abstract ledger tranport trait with WASM and native HID instantiations.

#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub mod hid;

/// APDU Transport wrapper for JS/WASM transports
#[cfg(all(target_arch = "wasm32"))]
pub mod wasm;
#[cfg(all(target_arch = "wasm32"))]
pub use wasm::LedgerTransport as DefaultTransport;

/// APDU Transport for native HID
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeTransport as DefaultTransport;

use crate::{errors::LedgerError, common::{APDUAnswer, APDUCommand}};

use async_trait::async_trait;

/// A Ledger device connection. This wraps the default transport type. In native code, this is
/// the `hidapi` library. When the `node` or `browser` feature is selected, it is a Ledger JS
/// transport library.
pub struct Ledger(DefaultTransport);

/// A Synchronous interface to the `Ledger` struct. This is provided for convenience, not for
/// ordinary use. Behind the scenes, this uses `futures::executor::block_on`, so it has
/// significant overhead compared to the async interface. `LedgerAsync` should be preferred
/// wherever possible.
pub trait LedgerSync: Sized {
    /// Init the connection to the device. This may fail if the device is already in use by some
    /// other process.
    fn init() -> Result<Self, LedgerError>;

    /// Exchange a packet with the device.
    fn exchange(&self, packet: &APDUCommand) -> Result<APDUAnswer, LedgerError>;

    /// Consume the connection, and release the resources it holds.
    fn close(self) {}
}

impl LedgerSync for Ledger {
    #[cfg(not(target_arch = "wasm32"))]
    fn init() -> Result<Self, LedgerError> {
        Ok(Self(DefaultTransport::new()?))
    }

    #[cfg(target_arch = "wasm32")]
    fn init() -> Result<Self, LedgerError> {
        let fut = DefaultTransport::create();
        let res: Result<DefaultTransport, wasm_bindgen::JsValue> = futures::executor::block_on(fut);
        let res: Result<DefaultTransport, LedgerError> = res.map_err(|err| err.into());
        Ok(Self(res?))
    }

    fn exchange(&self, packet: &APDUCommand) -> Result<APDUAnswer, LedgerError> {
       futures::executor::block_on(self.0.exchange(packet))
   }
}

#[async_trait(?Send)]
/// An asynchronous interface to the Ledger device. It is critical that the device have only one
/// connection active, so the `init` function acquires a lock on the device.
pub trait LedgerAsync: Sized {
    /// Init the connection to the device. This may fail if the device is already in use by some
    /// other process.
    async fn init() -> Result<Self, LedgerError>;

    /// Exchange a packet with the device.
    async fn exchange(&self, packet: &APDUCommand) -> Result<APDUAnswer, LedgerError>;

    /// Consume the connection, and release the resources it holds.
    fn close(self) {}
}

#[async_trait(?Send)]
impl LedgerAsync for Ledger {
    #[cfg(not(target_arch = "wasm32"))]
    async fn init() -> Result<Self, LedgerError> {
        Ok(Self(DefaultTransport::new()?))
    }

    #[cfg(target_arch = "wasm32")]
    async fn init() -> Result<Self, LedgerError> {
        let res: Result<DefaultTransport, wasm_bindgen::JsValue> = DefaultTransport::create().await;
        let res: Result<DefaultTransport, LedgerError> = res.map_err(|err| err.into());
        Ok(Self(res?))
    }

    async fn exchange(&self, packet: &APDUCommand) -> Result<APDUAnswer, LedgerError> {
       self.0.exchange(packet).await
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
