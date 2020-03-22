use std::io::{Read, Write};
use bitcoin_spv::types::{Hash256Digest};

use crate::types::primitives::{Ser, TxResult};

pub trait DigestMarker {}
impl DigestMarker for Hash256Digest {}

pub trait MarkedHash<T: DigestMarker> {
    fn new(hash: T) -> Self;
    fn internal(&self) -> T;
}

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct TXID(pub Hash256Digest);

impl Ser for TXID {
    fn serialized_length(&self) -> usize {
        32
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = Hash256Digest::default();
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
    where
        W: Write
    {
        Ok(writer.write(&self.0)?)
    }
}
impl MarkedHash<Hash256Digest> for TXID {
    fn new(hash: Hash256Digest) -> Self {
        Self(hash)
    }

    fn internal(&self) -> Hash256Digest {
        self.0
    }
}
impl From<Hash256Digest> for TXID {
    fn from(h: Hash256Digest) -> Self {
        Self::new(h)
    }
}
impl Into<Hash256Digest> for TXID {
    fn into(self) -> Hash256Digest {
        self.internal()
    }
}

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct WTXID(pub Hash256Digest);

impl Ser for WTXID {
    fn serialized_length(&self) -> usize {
        32
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = Hash256Digest::default();
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
    where
        W: Write
    {
        Ok(writer.write(&self.0)?)
    }
}
impl MarkedHash<Hash256Digest> for WTXID {
    fn new(hash: Hash256Digest) -> Self {
        Self(hash)
    }

    fn internal(&self) -> Hash256Digest {
        self.0
    }
}
impl From<Hash256Digest> for WTXID {
    fn from(h: Hash256Digest) -> Self {
        Self::new(h)
    }
}
impl Into<Hash256Digest> for WTXID {
    fn into(self) -> Hash256Digest {
        self.internal()
    }
}

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
