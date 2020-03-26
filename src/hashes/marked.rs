use std::io::{Write};
use bitcoin_spv::types::{Hash256Digest};

/// Marks a hash function digest.
pub trait DigestMarker {}
impl DigestMarker for Hash256Digest {}

/// A trait describing the interface for wrapped hashes. We wrap digests in this trait and name
/// them based on their function to prevent type-confusion between many different 32-byte digests.
pub trait MarkedDigest<T: DigestMarker> {
    fn new(hash: T) -> Self;
    fn internal(&self) -> T;
}

/// An interface for a haser that can be written to. Parameterized by the digest that it outputs.
pub trait MarkedDigestWriter<T: DigestMarker>: Default + Write {
    /// Consumes the hasher, calculates the digest from the written bytes. Returns a Digest
    /// of the parameterized type.
    fn finish(self) -> T;

    /// Calls finish, and wraps the result in a `MarkedDigest` type. Genericized to support any
    /// `MarkedDigest` that wraps the same parameterized type.
    fn finish_marked<M: MarkedDigest<T>>(self) -> M {
        MarkedDigest::new(self.finish())
    }
}
