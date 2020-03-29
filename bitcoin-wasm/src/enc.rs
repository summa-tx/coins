// use wasm_bindgen::prelude::*;
//
// use riemann_bitcoin::enc;
// use riemann_core::AddressEncoder;
//
// #[wasm_bindgen]
// pub struct MainnetEncoder(enc::MainnetEncoder);
//
// #[wasm_bindgen]
// impl MainnetEncoder {
//     /// Attempt to encode a `RecipientIdentifier` as an `Address`.
//     fn encode_address(s: &Script) -> Result<Self::Address, Self::Error> {
//         MainnetEncoder::encode_address(s)
//     }
//
//     /// Attempt to decode a `RecipientIdentifier` from an `Address`.
//     fn decode_address(addr: &Self::Address) -> Result<Self::RecipientIdentifier, Self::Error> {
//         MainnetEncoder::decode_address(addr)
//     }
//
//     /// Attempt to convert a string into an `Address`.
//     fn wrap_string(s: String) -> Result<Self::Address, Self::Error> {
//         MainnetEncoder::wrap_string(s)
//     }
// }
