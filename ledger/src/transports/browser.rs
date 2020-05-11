use js_sys;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    common::{APDUAnswer, APDUCommand},
    transports::errors::LedgerTransportError,
};

#[wasm_bindgen(module = "@ledgerhq/hw-transport-u2f")]
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
    pub type TransportU2F;

    /// `transport.exchange(apdu: Buffer): Promise<Buffer>`
    ///
    /// Seed [here](https://github.com/LedgerHQ/ledgerjs#an-unified-transport-interface)
    #[wasm_bindgen(method)]
    fn exchange(t: &TransportU2F, buf: &[u8]) -> js_sys::Promise;
}


/// Transport struct for non-wasm arch
#[wasm_bindgen]
pub struct LedgerTransport(TransportU2F);

/// Transport Impl for wasm
impl LedgerTransport {
    /// Send an APDU command to the device, and receive a response
    #[allow(clippy::needless_lifetimes)]
    pub async fn exchange<'a>(&self, apdu_command: &APDUCommand<'_>, buf: &'a mut [u8]) -> Result<APDUAnswer<'a>, LedgerTransportError> {
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
    /// Instantiate a new transport by calling `create` on the JS `@ledgerhq/hw-transport-*` mod
    pub async fn create() -> Result<LedgerTransport, JsValue> {
        let fut = JsFuture::from(TransportU2F::create());
        let transport = TransportU2F::from(fut.await?);
        Ok(Self(transport))
    }

    /// Instantiate from a js transport object
    pub fn from_js_transport(transport: TransportHID) -> Self {
        Self(transport)
    }
}
