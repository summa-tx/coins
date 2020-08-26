//! Holds utilites for working with cryptographic digests, and disambiguating digests via marker
//! traits.
//!
//! We want to wrap hashes in marked newtypes in order to prevent type-confusion between TXIDs,
//! sighashes, and other digests with the same length.

/// Marked hashes
pub mod marked;

/// Tooling for bitcoin-style double-sha2
pub mod hash256;

/// Tooling for blake2b256
pub mod blake2b256;

/// Tooling for sha3_256
pub mod sha3_256;

pub use blake2b256::*;
pub use hash256::*;
pub use marked::*;

pub use hash256::*;
pub use marked::*;
pub use blake2b256::*;
pub use sha3_256::*;
