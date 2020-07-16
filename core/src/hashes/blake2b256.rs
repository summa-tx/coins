use crate::hashes::marked::MarkedDigestWriter;
use blake2_rfc::blake2b::Blake2b;
use std::io::{Result as IOResult, Write};

/// A blake2b256 digest.
pub type Blake2b256Digest = [u8; 32];

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
        digest[..].copy_from_slice(&result[..]);
        digest
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
