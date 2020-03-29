//! Contains macros for use in this crate
//!
//! Some Notes on the macros:
//! - `wrap_struct` creates a new-type around a struct, and implements pass-throughs
//!   for serialization and deserialization
//! - `impl_simple_getter` creates a getter function for a pub property of a simple
//!   type. This works for any type natively supported by wasm_bindgen, e.g. u32.
//! - `impl_getter_passthrough` is equivalent to `impl_simple_getter` but wrapper
//!   getter functions instead of public properties.
//! - `impl_wrapped_getter` creates a getter function for public properties that are
//!   themselves structs that we have wrapped with `wrap_struct`. E.g. the TxIn's
//!   `outpoint` property.
//! - `impl_wrapped_getter_passthrough` creates a getter function for public getters
//!    that return structs that we have wrapped with `wrap_struct`. E.g. the `LegacyTx`
//!    class's `txid()` method;
//! - `impl_prefix_vec_access` generates getters and setters for prefix vecs



// This macro wraps and implements a wrapper around the `Ser` trait
// TODO: figure out why inspectable prints indexed characters
macro_rules! wrap_struct {
    ($module:ident::$name:ident) => {
        #[wasm_bindgen(inspectable)]
        #[derive(Clone, Debug, Default)]
        pub struct $name($module::$name);

        impl $name {
            pub fn inner(&self) -> $module::$name {
                self.0.clone()
            }
        }

        impl From<$module::$name> for $name {
            fn from(f: $module::$name) -> Self {
                Self(f)
            }
        }

        impl From<$name> for $module::$name {
            fn from(f: $name) -> Self {
                f.0
            }
        }

        #[wasm_bindgen]
        impl $name {

            #[wasm_bindgen(js_name = toJSON)]
            pub fn to_json(&self) -> String {
                match self.0.serialize_hex() {
                    Ok(s) => s,
                    Err(_) => "ERROR DURING SERIALIZATION".to_owned()
                }
            }

            #[wasm_bindgen(js_name = toString)]
            pub fn as_string(&self) -> String {
                match self.0.serialize_hex() {
                    Ok(s) => format!("{}: {}", stringify!($name), s),
                    Err(_) => "ERROR DURING SERIALIZATION".to_owned()
                }
            }

            #[allow(clippy::useless_asref)]
            pub fn deserialize(buf: &[u8]) -> Result<$name, JsValue> {
                $module::$name::deserialize(&mut buf.as_ref(), 0)
                    .map(Self::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            pub fn serialize(&self) -> Result<js_sys::Uint8Array, JsValue> {
                let mut v = vec![];
                self.0.serialize(&mut v)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                Ok(js_sys::Uint8Array::from(&v[..]))
            }

            pub fn deserialize_hex(s: String) -> Result<$name, JsValue> {
                $module::$name::deserialize_hex(s)
                    .map(Self::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            pub fn serialize_hex(&self) -> Result<String, JsValue> {
                self.0.serialize_hex()
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }
        }
    }
}

macro_rules! impl_simple_getter {
    ($class:ident, $prop:ident, $type:ty) => {
        #[wasm_bindgen]
        impl $class {
            #[wasm_bindgen(method, getter)]
            pub fn $prop(&self) -> $type {
                (self.0).$prop
            }
        }
    }
}

macro_rules! impl_getter_passthrough {
    ($class:ident, $prop:ident, $type:ty) => {
        #[wasm_bindgen]
        impl $class {
            #[wasm_bindgen(method, getter)]
            pub fn $prop(&self) -> $type {
                (self.0).$prop()
            }
        }
    }
}

macro_rules! impl_wrapped_getter {
    ($class:ident, $prop:ident, $type:ident) => {
        #[wasm_bindgen]
        impl $class {
            #[wasm_bindgen(method, getter)]
            pub fn $prop(&self) -> $type {
                (self.0).$prop.into()
            }
        }
    }
}

macro_rules! impl_wrapped_getter_passthrough {
    ($class:ident, $prop:ident, $type:ident) => {
        #[wasm_bindgen]
        impl $class {
            #[wasm_bindgen(method, getter)]
            pub fn $prop(&self) -> $type {
                (self.0).$prop().into()
            }
        }
    }
}

macro_rules! impl_prefix_vec_access {
    ($module:ident::$class:ident, $inner_module:ident::$inner_class:ident) => {
        #[wasm_bindgen]
        impl $class {
            #[wasm_bindgen(constructor)]
            pub fn new() -> $class {
                Self::null()
            }

            pub fn null() -> $class {
                $class($module::$class::null())
            }

            pub fn new_non_minimal(prefix_bytes: u8) -> Result<(), JsValue> {
                $class::new().set_prefix_len(prefix_bytes)
            }

            #[wasm_bindgen(method, getter)]
            pub fn length(&self) -> usize {
                self.0.len()
            }

            pub fn set_prefix_len(&mut self, prefix_len: u8) -> Result<(), JsValue> {
                self.0.set_prefix_len(prefix_len)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            pub fn len_prefix(&self) -> u8 {
                self.0.len_prefix()
            }

            pub fn push(&mut self, input: &$inner_class) {
                 self.0.push(input.0.clone())
            }

            pub fn get(&self, index: usize) -> $inner_class {
                self.0[index].clone().into()
            }

            pub fn set(&mut self, index: usize, item: &$inner_class) {
                self.0[index] = item.clone().into()
            }

            #[wasm_bindgen(method, getter)]
            pub fn items(&self) -> js_sys::Array {
                self.0.items()
                    .iter()
                    .map(Clone::clone)
                    .map($inner_class::from)
                    .map(JsValue::from)
                    .collect()
            }
        }
    }
}

macro_rules! impl_builders {
    ($leg:ident, $wit:ident, $enc:ident) => {
        #[wasm_bindgen(inspectable)]
        #[derive(Debug, Clone)]
        pub struct $leg(builder::LegacyBuilder<enc::$enc>);

        #[wasm_bindgen(inspectable)]
        #[derive(Debug, Clone)]
        pub struct $wit(builder::WitnessBuilder<enc::$enc>);

        impl From<builder::LegacyBuilder<enc::$enc>> for $leg {
            fn from(b: builder::LegacyBuilder<enc::$enc>) -> $leg {
                Self(b)
            }
        }

        impl From<builder::WitnessBuilder<enc::$enc>> for $wit {
            fn from(b: builder::WitnessBuilder<enc::$enc>) -> $wit {
                Self(b)
            }
        }

        impl Default for $leg {
            fn default() -> $leg {
                $leg::new()
            }
        }

        impl Default for $wit {
            fn default() -> $wit {
                $wit::new()
            }
        }

        #[wasm_bindgen]
        impl $leg {
            #[wasm_bindgen(constructor)]
            pub fn new() -> $leg {
                builder::LegacyBuilder::new().into()
            }

            pub fn version(self, version: u32) -> $leg {
                self.0.version(version).into()
            }

            pub fn spend(self, outpoint: BitcoinOutpoint, sequence: u32) -> $leg {
                self.0.spend(outpoint, sequence).into()
            }

            pub fn pay(self, value: u64, address: String) -> Result<$leg, JsValue> {
                let addr = enc::$enc::wrap_string(address)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                self.0.pay(value, &addr)
                    .map($leg::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            pub fn extend_inputs(self, inputs: Vin) -> $leg {
                self.0.extend_inputs(txin::Vin::from(inputs)).into()
            }

            pub fn extend_outputs(self, outputs: Vout) -> $leg {
                self.0.extend_outputs(txout::Vout::from(outputs)).into()
            }

            pub fn locktime(self, locktime: u32) -> $leg {
                self.0.locktime(locktime).into()
            }

            pub fn extend_witnesses(self, witnesses: TxWitness) -> $wit {
                self.0.extend_witnesses(Vec::<script::Witness>::from(witnesses)).into()
            }

            #[allow(clippy::wrong_self_convention)]
            pub fn as_witness(self) -> $wit {
                self.0.as_witness().into()
            }

            pub fn build(self) -> LegacyTx {
                self.0.build().into()
            }
        }

        #[wasm_bindgen]
        impl $wit {
            #[wasm_bindgen(constructor)]
            pub fn new() -> $wit {
                builder::WitnessBuilder::new().into()
            }

            pub fn version(self, version: u32) -> $wit {
                self.0.version(version).into()
            }

            pub fn spend(self, outpoint: BitcoinOutpoint, sequence: u32) -> $wit {
                self.0.spend(outpoint, sequence).into()
            }

            pub fn pay(self, value: u64, address: String) -> Result<$wit, JsValue> {
                let addr = enc::$enc::wrap_string(address)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                self.0.pay(value, &addr)
                    .map($wit::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            pub fn extend_inputs(self, inputs: Vin) -> $wit {
                self.0.extend_inputs(txin::Vin::from(inputs)).into()
            }

            pub fn extend_outputs(self, outputs: Vout) -> $wit {
                self.0.extend_outputs(txout::Vout::from(outputs)).into()
            }

            pub fn locktime(self, locktime: u32) -> $wit {
                self.0.locktime(locktime).into()
            }

            pub fn extend_witnesses(self, witnesses: TxWitness) -> $wit {
                self.0.extend_witnesses(Vec::<script::Witness>::from(witnesses)).into()
            }

            #[allow(clippy::wrong_self_convention)]
            pub fn as_legacy(self) -> $leg {
                self.0.as_legacy().into()
            }

            pub fn build(self) -> WitnessTx {
                self.0.build().into()
            }
        }
    }
}
