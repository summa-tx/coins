use bitcoin_spv::types::{Hash256Digest};

pub trait DigestMarker {}
impl DigestMarker for Hash256Digest {}

pub trait MarkedHash<T: DigestMarker> {
    fn new(hash: T) -> Self;
    fn internal(&self) -> T;
}
