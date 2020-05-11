use js_sys;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    common::{APDUAnswer, APDUCommand},
    transports::errors::LedgerTransportError,
};

#[wasm_bindgen(module = "@ledgerhq/hw-transport-node-hid")]
extern "C" {
    // NB:
    // This causes the JS glue to bind the variable `default1`
    // This took hours to figure out -_-
    pub type default;

    #[wasm_bindgen(static_method_of = default)]
    fn create() -> js_sys::Promise;
}

#[wasm_bindgen]
extern "C" {
    pub type TransportHID;

    /// `transport.exchange(apdu: Buffer): Promise<Buffer>`
    ///
    /// Seed [here](https://github.com/LedgerHQ/ledgerjs#an-unified-transport-interface)
    #[wasm_bindgen(method)]
    fn exchange(t: &TransportHID, buf: &[u8]) -> js_sys::Promise;
}


/// Transport struct for non-wasm arch
#[wasm_bindgen]
pub struct LedgerTransport(TransportHID);

/// Transport Impl for wasm
impl LedgerTransport {
    /// Send an APDU command to the device, and receive a response
    #[allow(clippy::needless_lifetimes)]
    pub async fn exchange<'a>(&self, apdu_command: &APDUCommand<'_>, buf: &'a mut [u8]) -> Result<APDUAnswer<'a>, LedgerTransportError> {
        let promise = self
            .0
            .exchange(&apdu_command.serialize());

        let future = JsFuture::from(promise);

        // Transport Error
        let result = future
            .await
            .map_err(|_| LedgerTransportError::APDUExchangeError)?;
        let answer = js_sys::Uint8Array::new(&result).to_vec();

        if answer.len() > buf.len() {
            // Buf too short
            return Err(LedgerTransportError::APDUExchangeError)
        }

        // response too short
        buf[..answer.len()].copy_from_slice(&answer[..]);
        Ok(APDUAnswer::from_answer(&buf[..answer.len()])
            .map_err(|_| LedgerTransportError::APDUExchangeError)?)
    }
}

#[wasm_bindgen]
impl LedgerTransport {
    /// Instantiate a new transport by calling `create` on the JS `@ledgerhq/hw-transport-*` mod
    pub async fn create() -> Result<LedgerTransport, JsValue> {
        let fut = JsFuture::from(default::create());
        let transport: TransportHID = fut.await?.into();
        Ok(Self(transport))
    }

    /// Instantiate from a js transport object
    pub fn from_js_transport(transport: TransportHID) -> Self {
        Self(transport)
    }

    #[doc(hidden)]
    // NB: this invalidates the JS ref to the wasm and makes the object unusable.
    pub async fn debug_send(self) -> Result<js_sys::Uint8Array, JsValue> {
        let mut response_buf = [0u8; 255];
        let command_buf: &[u8] = &[];

        // Ethereum `get_app_version`
        let command = APDUCommand {
            cla: 0xE0,
            ins: 0x06,
            p1: 0x00,
            p2: 0x00,
            data: command_buf.into(),
            response_len: None,
        };

        let answer = self.exchange(&command, &mut response_buf)
            .await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        let payload = answer.data().unwrap_or(&[]);
        Ok(js_sys::Uint8Array::from(payload))
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
