//! Holds Bitcoin-specific encoding tools. This includes an `AddressEncoder` that handles bech32
//! and base58check addresses, as well as newtypes that hold the Bitcoin network prefix
//! information for addresses.

pub mod bases;
pub mod encoder;

pub use bases::*;
pub use encoder::*;
