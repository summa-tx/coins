use wasm_bindgen::prelude::*;

use crate::{
    builder::{MainnetLegacyBuilder, TestnetLegacyBuilder, SignetLegacyBuilder},
    enc::{Address, MainnetEncoder, TestnetEncoder, SignetEncoder},
};


macro_rules! impl_network {
    ($network_name:ident, $builder_name:ident, $encoder_name:ident)=> {
        #[wasm_bindgen(inspectable)]
        #[derive(Debug)]
        pub struct $network_name;

        #[wasm_bindgen]
        impl $network_name {
            pub fn tx_builder() -> $builder_name {
                $builder_name::new()
            }

            pub fn encode_address(s: &[u8]) -> Result<Address, JsValue> {
                $encoder_name::encode_address(s)

            }

            /// Attempt to decode a `RecipientIdentifier` from an `Address`.
            pub fn decode_address(addr: Address) -> Result<js_sys::Uint8Array, JsValue> {
                $encoder_name::decode_address(addr)
            }

            /// Attempt to convert a string into an `Address`.
            pub fn wrap_string(s: String) -> Result<Address, JsValue> {
                $encoder_name::wrap_string(s)
            }
        }
    }
}

impl_network!(BitcoinMainnet, MainnetLegacyBuilder, MainnetEncoder);
impl_network!(BitcoinTestnet, TestnetLegacyBuilder, TestnetEncoder);
impl_network!(BitcoinSignet, SignetLegacyBuilder, SignetEncoder);
