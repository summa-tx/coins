use wasm_bindgen::prelude::*;

use crate::{ser::Ser, bitcoin::types::txin::BitcoinOutpoint};

#[wasm_bindgen]
pub fn make_outpoint() -> String {
    BitcoinOutpoint::default().serialize_hex().unwrap()
}
