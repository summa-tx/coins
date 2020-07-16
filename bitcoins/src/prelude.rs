pub use crate::{
    builder::*,
    enc::*,
    hashes::{TXID, WTXID, BlockHash},
    types::*,
};

pub use bitcoin_spv::types::Hash256Digest;
pub use coins_core::prelude::*;

// TODO: break into own module
/// A raw bitcoin block header
#[derive(Copy, Clone)]
pub struct RawHeader([u8; 80]);

impl ByteFormat for RawHeader {
    type Error = coins_core::ser::SerError;

    fn serialized_length(&self) -> usize {
        80
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> Result<Self, Self::Error>
    where
        R: std::io::Read,
        Self: std::marker::Sized,
    {
        let mut header = [0u8; 80];
        reader.read_exact(&mut header)?;
        Ok(header.into())
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: std::io::Write,
    {
        writer.write_all(self.as_ref())?;
        Ok(80)
    }
}

impl std::fmt::Debug for RawHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RawHeader")
         .field(&self.as_ref())
         .finish()
    }
}

impl From<[u8; 80]> for RawHeader {
    fn from(bytes: [u8; 80]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for RawHeader {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

#[cfg(any(feature = "mainnet", feature = "testnet", feature = "signet"))]
pub use crate::defaults::*;
