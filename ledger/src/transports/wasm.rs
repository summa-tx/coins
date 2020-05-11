use js_sys;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;


use crate::{
    common::{APDUAnswer, APDUCommand},
    transports::errors::LedgerTransportError,
};

#[wasm_bindgen]
extern "C" {
    pub type JsLedgerTransport;

    /// Duck typed (structural) access to the transport interface.
    ///
    /// `transport.exchange(apdu: Buffer): Promise<Buffer>`
    ///
    /// Seed [here](https://github.com/LedgerHQ/ledgerjs#an-unified-transport-interface)
    #[wasm_bindgen(method, structural)]
    fn exchange(t: &JsLedgerTransport, buf: &[u8]) -> js_sys::Promise;
}


/// Transport struct for non-wasm arch
#[wasm_bindgen]
pub struct LedgerTransport(JsLedgerTransport);

/// Transport Impl for wasm
impl LedgerTransport {
    /// Send an APDU command to the device, and receive a response
    #[allow(clippy::needless_lifetimes)]
    pub async fn exchange<'a>(&self, apdu_command: APDUCommand, buf: &'a mut [u8]) -> Result<APDUAnswer<'a>, LedgerTransportError> {
        let promise = self
            .0
            .exchange(&apdu_command.serialize());

        let future = JsFuture::from(promise);
        let result = future
            .await
            .map_err(|_| LedgerTransportError::APDUExchangeError)?;

        let answer = js_sys::Uint8Array::new(&result).to_vec();
        if answer.len() > buf.len() {
            return Err(LedgerTransportError::APDUExchangeError)
        }
        buf[..answer.len()].copy_from_slice(&answer[..]);

        // if the reply is < 2 bytes, this is a serious error
        if answer.len() < 2 {
            return Err(LedgerTransportError::APDUExchangeError);
        }

        Ok(APDUAnswer::from_answer(buf).map_err(|_| LedgerTransportError::APDUExchangeError)?)
    }
}

#[wasm_bindgen]
impl LedgerTransport {
    /// Instantiate a new transport from the JS `@ledgerhq/hw-transport-*` instance.
    #[wasm_bindgen(constructor)]
    pub fn new(transport: JsLedgerTransport) -> Self {
        Self(transport)
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
