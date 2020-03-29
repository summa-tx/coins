// This macro wraps and implements a wrapper around the `Ser` trait
// TODO: figure out why inspectable prints indexed characters
macro_rules! wrap_struct {
    ($module:ident::$name:ident) => {
        #[wasm_bindgen(inspectable)]
        #[derive(Clone, Debug)]
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
            pub fn to_string(&self) -> String {
                match self.0.serialize_hex() {
                    Ok(s) => format!("{}: {}", stringify!($name), s),
                    Err(_) => "ERROR DURING SERIALIZATION".to_owned()
                }
            }

            pub fn deserialize(buf: &[u8]) -> Result<$name, JsValue> {
                $module::$name::deserialize(&mut buf.as_ref(), 0)
                    .map(|v| Self(v))
                    .map_err(|e| JsValue::from(WasmError::from(e)))
            }

            pub fn serialize(&self) -> Result<js_sys::Uint8Array, JsValue> {
                let mut v = vec![];
                self.0.serialize(&mut v).map_err(|e| JsValue::from(WasmError::from(e)))?;
                Ok(js_sys::Uint8Array::from(&v[..]))
            }

            pub fn deserialize_hex(s: String) -> Result<$name, JsValue> {
                $module::$name::deserialize_hex(s)
                    .map(|v| Self(v))
                    .map_err(|e| JsValue::from(WasmError::from(e)))
            }

            pub fn serialize_hex(&self) -> Result<String, JsValue> {
                self.0.serialize_hex()
                    .map_err(|e| JsValue::from(WasmError::from(e)))
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
                $type((self.0).$prop)
            }
        }
    }
}
