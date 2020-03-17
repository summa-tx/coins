extern crate hex;

mod de;
mod error;
mod ser;

// pub use de::{from_str, Deserializer};
pub use error::{Error, Result};
pub use ser::{to_bytes, Serializer};

use serde::Serialize;

pub trait Serializable: Serialize {
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes(&self).expect("serialization failed")
    }

    fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }
}
