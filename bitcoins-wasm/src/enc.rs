//! Defines parameterized Bitcoin encoders for Mainnet, Testnet, and Signet.

use serde::ser::{Serialize, Serializer};
use wasm_bindgen::prelude::*;

use coins_core::enc::AddressEncoder;

use bitcoins::enc;

/// A wrapper type for Bitcoin addresses. Contains an instance of the address enum.
#[wasm_bindgen]
pub struct Address(enc::Address);

impl From<enc::Address> for Address {
    fn from(a: enc::Address) -> Address {
        Address(a)
    }
}

impl From<Address> for enc::Address {
    fn from(a: Address) -> enc::Address {
        a.0
    }
}

#[wasm_bindgen]
impl Address {
    /// Convert the address to a string.
    #[wasm_bindgen(method, getter)]
    pub fn as_string(&self) -> String {
        self.0.as_string()
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.as_string())
    }
}

impl_encoder!(
    /// An encoder for Bitcoin Mainnet
    MainnetEncoder
);
impl_encoder!(
    /// An encoder for Bitcoin Tesnet
    TestnetEncoder
);
impl_encoder!(
    /// An encoder for Bitcoin Signet
    SignetEncoder
);
