use std::io::{Write};

use crate::hashes::marked::{MarkedHash, DigestMarker};


pub trait HashWriter<T: DigestMarker>: Default + Write {
    fn finish(self) -> T;

    fn finish_marked<M: MarkedHash<T>>(self) -> M {
        MarkedHash::new(self.finish())
    }
}
