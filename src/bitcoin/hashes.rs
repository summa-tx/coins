//! This module holds `MarkedDigest` types used by Bitcoin transactions. Currently we represent
//! only `TXID`s and `WTXID`s. In the future we will also represent

use std::io::{Read, Write};
use bitcoin_spv::types::{Hash256Digest};

use crate::{
    hashes::marked::{MarkedDigest},
    ser::{Ser, SerResult}
};

macro_rules! mark_hash256 {
    ($hash_name:ident) => {
        #[doc = "A Marked Hash256Digest that represents a $hash_name"]
        #[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
        pub struct $hash_name(pub Hash256Digest);
        impl Ser for $hash_name {
            fn serialized_length(&self) -> usize {
                32
            }

            fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
            where
            R: Read,
            Self: std::marker::Sized
            {
                let mut buf = <Hash256Digest>::default();
                reader.read_exact(&mut buf)?;
                Ok(Self(buf))
            }

            fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
            where
            W: Write
            {
                Ok(writer.write(&self.0)?)
            }
        }
        impl MarkedDigest for $hash_name {
            type Digest = Hash256Digest;
            fn new(hash: Hash256Digest) -> Self {
                Self(hash)
            }

            fn internal(&self) -> Hash256Digest {
                self.0
            }
        }
        impl From<Hash256Digest> for $hash_name {
            fn from(h: Hash256Digest) -> Self {
                Self::new(h)
            }
        }
        impl Into<Hash256Digest> for $hash_name {
            fn into(self) -> Hash256Digest {
                self.internal()
            }
        }
    }
}

mark_hash256!(TXID);
mark_hash256!(WTXID);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_serializes_and_derializes_hash256digests() {
        let cases = [
            (TXID::default(), "0000000000000000000000000000000000000000000000000000000000000000"),
        ];
        for case in cases.iter() {
            let digest = TXID::deserialize_hex(case.1.to_owned()).unwrap();
            assert_eq!(digest.serialized_length(), 32);
            assert_eq!(digest, case.0);
            assert_eq!(digest.serialize_hex().unwrap(), case.1);
            assert_eq!(case.0.serialize_hex().unwrap(), case.1);
        }
    }
}
