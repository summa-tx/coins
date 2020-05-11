//! Abstract ledger tranport trait with WASM and native HID instantiations.

/// APDU Errors
pub mod errors;

#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub mod hid;

pub use errors::LedgerTransportError;

/// APDU Transport wrapper for JS/WASM transports
#[cfg(target_arch = "wasm32")]
pub mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::LedgerTransport as Transport;

/// APDU Transport for native HID
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeTransport as Transport;


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
