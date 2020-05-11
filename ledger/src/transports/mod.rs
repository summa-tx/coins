//! Abstract ledger tranport trait with WASM and native HID instantiations.

/// APDU Errors
pub mod errors;

#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub mod hid;

/// APDU Transport wrapper for JS/WASM transports
#[cfg(all(target_arch = "wasm32", feature = "node", not(feature = "browser")))]
pub mod node;
#[cfg(all(target_arch = "wasm32", feature = "node", not(feature = "browser")))]
pub use node::LedgerTransport as DefaultTransport;

/// APDU Transport wrapper for JS/WASM transports
#[cfg(all(target_arch = "wasm32", feature = "browser", not(feature = "node")))]
pub mod browser;
#[cfg(all(target_arch = "wasm32", feature = "browser", not(feature = "node")))]
pub use browser::LedgerTransport as DefaultTransport;

/// APDU Transport for native HID
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeTransport as DefaultTransport;


/// Marker trait for transports. Use this until we get async-trait support working
pub trait APDUExchanger {
    /// Exchange a packet synchronously. This uses `futures::executor::block_on` to run the future
    /// in the current thread.
    fn exchange_sync<'a>(&self, apdu_command: &APDUCommand, buf: &'a mut [u8]) -> Result<APDUAnswer<'a>, LedgerTransportError>;
}

impl APDUExchanger for DefaultTransport {
    fn exchange_sync<'a>(&self, apdu_command: &APDUCommand, buf: &'a mut [u8]) -> Result<APDUAnswer<'a>, LedgerTransportError> {
        futures::executor::block_on(self.exchange(apdu_command, buf))
    }
}

pub use errors::LedgerTransportError;
pub use crate::common::{APDUAnswer, APDUCommand, APDUResponseCodes};



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
