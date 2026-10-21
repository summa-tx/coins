//! Abstract ledger transport trait with a native HID instantiation.

use std::time::Duration;

pub mod native;
pub use native::{DeviceId, HidTransport};

use crate::{
    common::{ApduAnswer, ApduCommand},
    errors::LedgerError,
};

/// An asynchronous interface to a Ledger device.
pub trait LedgerTransport {
    /// Exchange a packet. Transports SHOULD respect the timeout, but are free
    /// to choose how to do that.
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
