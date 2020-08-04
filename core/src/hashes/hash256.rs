use sha2::{Digest as Sha2Digest, Sha256};
use std::io::{Read, Result as IOResult, Write};

use bitcoin_spv::types::Hash256Digest;

use crate::{
    hashes::marked::{Digest, MarkedDigestWriter},
    ser::{ByteFormat, SerError, SerResult},
};

impl Digest for Hash256Digest {}

impl ByteFormat for Hash256Digest {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        32
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let mut buf = Hash256Digest::default();
        reader.read_exact(buf.as_mut())?;
        Ok(buf)
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
        Ok(writer.write(self.as_ref())?)
    }
}

/// A struct that exposes a Bitcoin-style Hash256 `Write` interface by wrapping an internal SHA2
/// instance.
///
/// ```
/// # use std::io::{Result};
/// use std::io::Write;
/// use coins_core::hashes::{Hash256Writer, MarkedDigestWriter};
///
/// # fn main() -> Result<()> {
/// let mut w = Hash256Writer::default();
/// # let data = [0u8; 32];
///
/// // Writing more than once will update the hasher.
/// w.write(&data)?;
///
/// // Call finish to consume the hasher and produce the digest.
/// let digest = w.finish();
/// # Ok(())
/// }
/// ```
#[derive(Default)]
pub struct Hash256Writer {
    internal: Sha256,
}

impl Write for Hash256Writer {
    fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
        self.internal.write(buf)
    }
    fn flush(&mut self) -> IOResult<()> {
        Ok(())
    }
}

impl MarkedDigestWriter<Hash256Digest> for Hash256Writer {
    fn finish(self) -> Hash256Digest {
        let first = self.internal.result();
        let second = Sha256::digest(&first);
        let mut digest = Hash256Digest::default();
        digest.as_mut().copy_from_slice(&second[..]);
        digest
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ser::ByteFormat;
    #[test]
    fn it_ignores_flush() {
        let mut w = Hash256Writer::default();
        w.write(&[0]).unwrap();
        w.flush().unwrap();
        assert_eq!(
            w.finish(),
            Hash256Digest::deserialize_hex(
                "1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a"
            )
            .unwrap()
        );
    }
}
