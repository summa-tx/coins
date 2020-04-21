//! Holds utilites for working with cryptographic digests, and disambiguating digests via marker
//! traits.
//!
//! We want to wrap hashes in marked newtypes in order to prevent type-confusion between TXIDs,
//! sighashes, and other digests with the same length.

/// Marked hashes
pub mod marked;

/// Tooling for bitcoin-style double-sha2
pub mod hash256;

pub use hash256::*;
pub use marked::*;
