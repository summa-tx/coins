use std::io::{Write, Result as IOResult};
use sha2::{Digest, Sha256};

use bitcoin_spv::types::{Hash256Digest};

use crate::hashes::{
    writer::{HashWriter},
};

#[derive(Default)]
pub struct Hash256Writer {
    internal: Sha256
}

impl Write for Hash256Writer {
    fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
        self.internal.write(buf)
    }

    fn flush(&mut self) -> IOResult<()> {
        Ok(())
    }
}

impl HashWriter<Hash256Digest> for Hash256Writer {
    fn finish(self) -> Hash256Digest {
        let first = self.internal.result();
        let second = Sha256::digest(&first);
        let mut digest = Hash256Digest::default();
        digest[..].copy_from_slice(&second[..]);
        digest
    }
}
