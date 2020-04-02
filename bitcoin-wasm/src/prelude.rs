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
macro_rules! wrap_struct {
    (
        $(#[$outer:meta])*
        $module:ident::$name:ident
    ) => {
        $(#[$outer])*
        #[wasm_bindgen(inspectable)]
        #[derive(Clone, Debug, Default)]
        pub struct $name($module::$name);

        impl $name {
            /// Return a clone of the underlying object.
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

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer
            {
                let mut i = serializer.serialize_struct(stringify!($name), 1)?;
                i.serialize_field(stringify!($name), &self.0.to_json())?;
                i.end()
            }
        }

        #[wasm_bindgen]
        impl $name {
            /// Deserialize from a `Uint8Array`
            #[allow(clippy::useless_asref)]
            pub fn deserialize(buf: &[u8]) -> Result<$name, JsValue> {
                $module::$name::deserialize(&mut buf.as_ref(), 0)
                    .map(Self::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            /// Serialize to a `Uint8Array`
            pub fn serialize(&self) -> Result<js_sys::Uint8Array, JsValue> {
                let mut v = vec![];
                self.0.serialize(&mut v)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                Ok(js_sys::Uint8Array::from(&v[..]))
            }

            /// Deserialize from hex.
            pub fn deserialize_hex(s: String) -> Result<$name, JsValue> {
                $module::$name::deserialize_hex(s)
                    .map(Self::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            /// Serialize to a hex string.
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

            #[wasm_bindgen(method, getter)]
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

        /// LegacyBuilder provides a struct on which we implement `TxBuilder` for legacy Bitcoin
        /// Transactions. Its associated types are the standard Bitcoin `LegacyTx`, and `WitnessTx`,
        /// and the WitnessBuilder. It is parameterized with an address encoder, so that the same
        /// struct and logic can be used on mainnet and testnet.
        ///
        /// It can be explicitly converted to a WitnessBuilder using `as_witness`, or implicitly
        /// via `extend_witnesses`.
        #[wasm_bindgen(inspectable)]
        #[derive(Debug, Clone)]
        pub struct $leg(builder::LegacyBuilder<enc::$enc>);

        /// WitnessBuilder implements `TxBuilder` and `WitTxBuilder`. The only difference between
        /// `WitnessBuilder` and `LegacyBuilder` is that `WitnessBuilder` builds Witness transactions.
        /// This is implemented by having `WitnessBuilder` contain an internal `LegacyBuilder` which all
        /// non-witness updates are applied to.
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
            /// Instantiate a new builder
            pub fn new() -> $leg {
                builder::LegacyBuilder::new().into()
            }

            /// Set the builder version
            pub fn version(self, version: u32) -> $leg {
                self.0.version(version).into()
            }

            /// Spend an outpoint
            pub fn spend(self, outpoint: BitcoinOutpoint, sequence: u32) -> $leg {
                self.0.spend(outpoint, sequence).into()
            }

            /// Pay an address
            pub fn pay(self, value: u64, address: &str) -> Result<$leg, JsValue> {
                let addr = enc::$enc::string_to_address(address)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                self.0.pay(value, &addr)
                    .map($leg::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            /// Extend the vin with several inputs
            pub fn extend_inputs(self, inputs: Vin) -> $leg {
                self.0.extend_inputs(txin::Vin::from(inputs)).into()
            }

            /// Extend the vout with several outputs
            pub fn extend_outputs(self, outputs: Vout) -> $leg {
                self.0.extend_outputs(txout::Vout::from(outputs)).into()
            }

            /// Set the locktime
            pub fn locktime(self, locktime: u32) -> $leg {
                self.0.locktime(locktime).into()
            }

            /// Add witnesses and implicitly convert to a witness builder.
            pub fn extend_witnesses(self, witnesses: TxWitness) -> $wit {
                self.0.extend_witnesses(Vec::<script::Witness>::from(witnesses)).into()
            }

            /// Explicitly convert to a witness builder
            #[allow(clippy::wrong_self_convention)]
            pub fn as_witness(self) -> $wit {
                self.0.as_witness().into()
            }

            /// Consume the builder and produce a transaction
            pub fn build(self) -> LegacyTx {
                self.0.build().into()
            }
        }

        #[wasm_bindgen]
        impl $wit {
            /// Instantiate a new builder#[wasm_bindgen(constructor)]
            pub fn new() -> $wit {
                builder::WitnessBuilder::new().into()
            }

            /// Set the builder version
            pub fn version(self, version: u32) -> $wit {
                self.0.version(version).into()
            }

            /// Spend an outpoint
            pub fn spend(self, outpoint: BitcoinOutpoint, sequence: u32) -> $wit {
                self.0.spend(outpoint, sequence).into()
            }

            /// Pay an address
            pub fn pay(self, value: u64, address: &str) -> Result<$wit, JsValue> {
                let addr = enc::$enc::string_to_address(address)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                self.0.pay(value, &addr)
                    .map($wit::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            /// Extend the vin with several inputs
            pub fn extend_inputs(self, inputs: Vin) -> $wit {
                self.0.extend_inputs(txin::Vin::from(inputs)).into()
            }

            /// Extend the vout with several outputs
            pub fn extend_outputs(self, outputs: Vout) -> $wit {
                self.0.extend_outputs(txout::Vout::from(outputs)).into()
            }

            /// Set the locktime
            pub fn locktime(self, locktime: u32) -> $wit {
                self.0.locktime(locktime).into()
            }

            /// Add witnesses
            pub fn extend_witnesses(self, witnesses: TxWitness) -> $wit {
                self.0.extend_witnesses(Vec::<script::Witness>::from(witnesses)).into()
            }

            /// Explicitly convert to a legacy builder
            #[allow(clippy::wrong_self_convention)]
            pub fn as_legacy(self) -> $leg {
                self.0.as_legacy().into()
            }

            /// Consume the builder and produce a transaction
            pub fn build(self) -> WitnessTx {
                self.0.build().into()
            }
        }
    }
}

macro_rules! impl_encoder {
    (
        $(#[$outer:meta])*
        $module:ident::$enc_name:ident
    ) => {
        $(#[$outer])*
        #[wasm_bindgen]
        pub struct $enc_name;

        #[wasm_bindgen]
        impl $enc_name {
            /// Attempt to encode a `RecipientIdentifier` as an `Address`.
            pub fn encode_address(s: &[u8]) -> Result<Address, JsValue> {
                $module::$enc_name::encode_address(&script::ScriptPubkey::from(s))
                    .map(Address::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }

            /// Attempt to decode a `RecipientIdentifier` from an `Address`.
            pub fn decode_address(addr: Address) -> Result<js_sys::Uint8Array, JsValue> {
                let decoded = $module::$enc_name::decode_address(&addr.into())
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)?;
                Ok(js_sys::Uint8Array::from(decoded.items()))
            }

            /// Attempt to convert a string into an `Address`.
            pub fn string_to_address(s: &str) -> Result<Address, JsValue> {
                $module::$enc_name::string_to_address(s)
                    .map(Address::from)
                    .map_err(WasmError::from)
                    .map_err(JsValue::from)
            }
        }
    }
}

macro_rules! impl_network {
    (
        $(#[$outer:meta])*
        $network_name:ident, $builder_name:ident, $encoder_name:ident
    )=> {
        #[wasm_bindgen(inspectable)]
        #[derive(Debug)]
        pub struct $network_name;

        #[wasm_bindgen]
        impl $network_name {
            /// Return a new transaction builder for this network.
            pub fn tx_builder() -> $builder_name {
                $builder_name::new()
            }

            /// Encode a Uint8Array as an address with this network's version info.
            /// Throws for non-standard scripts
            pub fn encode_address(s: &[u8]) -> Result<Address, JsValue> {
                $encoder_name::encode_address(s)
            }

            /// Attempt to decode a `RecipientIdentifier` from an `Address`.
            /// Throws if the detected version info does not match this network.
            pub fn decode_address(addr: Address) -> Result<js_sys::Uint8Array, JsValue> {
                $encoder_name::decode_address(addr)
            }

            /// Attempt to convert a string into an `Address`.
            /// Throws if the string is not an address for this network.
            pub fn string_to_address(s: &str) -> Result<Address, JsValue> {
                $encoder_name::string_to_address(s)
            }
        }
    }
}
