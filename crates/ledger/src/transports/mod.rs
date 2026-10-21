//! Abstract ledger transport trait with a native HID instantiation.

use std::{fmt, time::Duration};

pub mod native;
pub use native::{HidDeviceId, HidTransport, NativeTransportError};

use crate::{
    Model,
    common::{ApduAnswer, ApduCommand},
    errors::LedgerError,
};

/// What identifies a Ledger on any transport: its model and serial number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceIdentity<'a> {
    model: Model,
    serial_number: Option<&'a str>,
}

impl<'a> DeviceIdentity<'a> {
    /// Identify a device by model and, if it reports one, serial number.
    pub const fn new(model: Model, serial_number: Option<&'a str>) -> Self {
        Self {
            model,
            serial_number,
        }
    }

    /// The hardware model.
    pub const fn model(&self) -> Model {
        self.model
    }

    /// The serial number, if the device reports one.
    pub const fn serial_number(&self) -> Option<&str> {
        self.serial_number
    }
}

/// `Nano X (0001)`, or `Nano X` with no serial number.
impl fmt::Display for DeviceIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.model)?;
        if let Some(serial) = &self.serial_number {
            write!(f, " ({serial})")?;
        }
        Ok(())
    }
}

/// An asynchronous interface to a Ledger device.
pub trait LedgerTransport {
    /// The device this transport talks to, if it knows.
    fn identity(&self) -> Option<DeviceIdentity<'_>>;

    /// Exchange a packet. Transports SHOULD respect the timeout, but are free
    /// to choose how to do that. A transport reports a timeout as
    /// [`LedgerError::Timeout`] and its own failures as
    /// [`LedgerError::Transport`].
    ///
    /// [`Ledger::exchange`](crate::Ledger::exchange) calls this inside a span
    /// with an empty `device` field. A transport that knows its device may
    /// record it on the current span.
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
