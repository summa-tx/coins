use std::io::{Write};
use bitcoin_spv::types::{Hash256Digest};


pub trait DigestMarker {}
impl DigestMarker for Hash256Digest {}

pub trait MarkedHash<T: DigestMarker> {
    fn new(hash: T) -> Self;
    fn internal(&self) -> T;
}

pub trait MarkedHashWriter<T: DigestMarker>: Default + Write {
    fn finish(self) -> T;

    fn finish_marked<M: MarkedHash<T>>(self) -> M {
        MarkedHash::new(self.finish())
    }
}
