//! Holds utilites for working with cryptographic digests, and disambiguating digests via marker
//! traits.
//!
//! We want to wrap hashes in marked newtypes in order to prevent type-confusion between TXIDs,
//! sighashes, and other digests with the same length.

pub mod marked;
pub mod hash256;

pub use marked::*;
pub use hash256::*;
