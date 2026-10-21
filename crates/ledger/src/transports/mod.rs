//! Abstract ledger transport trait with a native HID instantiation.

use std::time::Duration;

/// APDU Transport for native HID. Wraps
/// [`TransportNativeHID`][native::hid::TransportNativeHID] in a
/// thread managing the IO.
pub mod native;
pub use native::LedgerHandle;

use crate::{
    common::{ApduAnswer, ApduCommand},
    errors::LedgerError,
};

/// An asynchronous interface to a Ledger device.
///
/// A transport owns one connection to the device. APDUs on a connection must
/// never be interleaved, so [`Ledger`](crate::Ledger) holds its transport
/// exclusively and `exchange` takes `&mut self`.
///
/// Implementations build their replies with [`ApduAnswer::from_answer`] and
/// return a non-success status word as an error with
/// [`ApduAnswer::into_result`]. See [`Ledger`](crate::Ledger) for an example.
pub trait LedgerTransport {
    /// Exchange a packet, waiting up to `timeout` for each report of the
    /// reply. `None` waits indefinitely.
    fn exchange(
        &mut self,
        packet: ApduCommand,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<ApduAnswer, LedgerError>> + Send;
}

#[cfg(test)]
#[path = "../../ai-tests/transports/mod.rs"]
pub(crate) mod ai_tests;

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
