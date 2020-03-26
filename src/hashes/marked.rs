use std::io::{Write};
use bitcoin_spv::types::{Hash256Digest};

use crate::ser::{Ser};

/// Marks a hash function digest.
pub trait Digest: Default + Ser {}
impl Digest for Hash256Digest {}

/// A trait describing the interface for wrapped hashes. We wrap digests in this trait and name
/// them based on their function to prevent type-confusion between many different 32-byte digests.
pub trait MarkedDigest: Default + Ser {
    /// The associated Digest type that is marked.
    type Digest: Digest;
    /// Wrap a digest of the appropriate type in the marker.
    fn new(hash: Self::Digest) -> Self;

    /// Return a copy of the internal digest.
    fn internal(&self) -> Self::Digest;
}

/// An interface for a haser that can be written to. Parameterized by the digest that it outputs.
pub trait MarkedDigestWriter<T: Digest>: Default + Write {
    /// Consumes the hasher, calculates the digest from the written bytes. Returns a Digest
    /// of the parameterized type.
    fn finish(self) -> T;

    /// Calls finish, and wraps the result in a `MarkedDigest` type. Genericized to support any
    /// `MarkedDigest` that wraps the same parameterized type.
    fn finish_marked<M: MarkedDigest<Digest = T>>(self) -> M {
        MarkedDigest::new(self.finish())
    }
}
