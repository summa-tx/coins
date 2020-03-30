use js_sys;
use wasm_bindgen::prelude::*;
use serde::ser::{Serialize, Serializer};

use riemann_core::{
    enc::{AddressEncoder},
    primitives::{PrefixVec},
};

use riemann_bitcoin::{enc, script};

use crate::errors::{WasmError};

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
    #[wasm_bindgen(method, getter)]
    pub fn as_string(&self) -> String {
        self.0.as_string()
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        serializer.serialize_str(&self.0.as_string())
    }
}

impl_encoder!(enc::MainnetEncoder);
impl_encoder!(enc::TestnetEncoder);
impl_encoder!(enc::SignetEncoder);
