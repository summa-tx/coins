use blake2_rfc::blake2b::Blake2b;
use std::io::{Read, Result as IOResult, Write};

use crate::{
    hashes::marked::{Digest, MarkedDigestWriter},
    ser::{ByteFormat, SerError, SerResult},
    impl_hex_serde,
};

/// A blake2b256 digest.
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Blake2b256Digest([u8; 32]);

#[macro_use]
impl_hex_serde!(
    Blake2b256Digest
);

impl Digest for Blake2b256Digest {}

impl ByteFormat for Blake2b256Digest {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        32
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let mut buf = Blake2b256Digest::default();
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

/// A struct that exposes a Blake256 `Write` interface.
///
/// ```
/// # use std::io::{Result};
/// use std::io::Write;
/// use coins_core::hashes::{Blake2b256Writer, MarkedDigestWriter};
///
/// # fn main() -> Result<()> {
/// let mut w = Blake2b256Writer::default();
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
pub struct Blake2b256Writer {
    internal: Blake2b,
}

impl Default for Blake2b256Writer {
    fn default() -> Blake2b256Writer {
        Blake2b256Writer {
            internal: Blake2b::new(32),
        }
    }
}

impl Write for Blake2b256Writer {
    fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
        self.internal.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> IOResult<()> {
        Ok(())
    }
}

impl MarkedDigestWriter<Blake2b256Digest> for Blake2b256Writer {
    fn finish(self) -> Blake2b256Digest {
        let digest = self.internal.finalize();
        let result = digest.as_bytes();

        let mut digest = Blake2b256Digest::default();
        digest.as_mut().copy_from_slice(&result[..]);
        digest
    }
}

#[cfg_attr(tarpaulin, skip)]
impl core::fmt::Debug for Blake2b256Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Blake2b256Digest: {:x?}", self.0)
    }
}

impl From<[u8; 32]> for Blake2b256Digest {
    fn from(buf: [u8; 32]) -> Self {
        Self(buf)
    }
}

impl AsRef<[u8; 32]> for Blake2b256Digest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsMut<[u8; 32]> for Blake2b256Digest {
    fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::ser::ByteFormat;

    #[test]
    fn it_hashes_blake2b256() {
        let mut w = Blake2b256Writer::default();
        w.write(&[00, 00]).unwrap();
        let result = w.finish();
        assert_eq!(
            result,
            Blake2b256Digest::deserialize_hex(
                "9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af6162ab145a6"
            )
            .unwrap()
        );
    }
}
