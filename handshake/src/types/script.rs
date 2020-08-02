//! This module holds a Script struct and a HandshakeScript trait.
//! Handshake is segwit only, meaning that there are no ScriptPubkeys
//! and there are no opcodes encoded in an address. Addresses are
//! bech32 and depending on the version and data, a Script is created
//! at runtime.

/// A wrapped script.
pub trait HandshakeScript {}

wrap_prefixed_byte_vector!(
    /// A Script is marked Vec<u8> for use as an opaque `Script` in `SighashArgs`
    /// structs.
    ///
    /// `Script::null()` and `Script::default()` return the empty byte vector with a 0
    /// prefix, which represents numerical 0, boolean `false`, or null bytestring.
    Script
);

impl HandshakeScript for Script {}
