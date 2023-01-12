//! This module holds `MarkedDigest` types used by Handshake transactions. Currently we represent
//! only `TXID`s and `WTXID`s. In the future we may also represent sighash digests this way.
//! It also holds a blake2b160 wrapper function.

use blake2_rfc::blake2b::Blake2b;

use coins_core::{hashes::Blake2b256, impl_hex_serde, marked_digest};

marked_digest!(
    /// An unmarked Blake2b256 digest output
    Blake2b256Digest,
    Blake2b256
);

marked_digest!(
    /// A marked Blake2b256 representing transaction IDs
    TXID,
    Blake2b256
);
marked_digest!(
    /// A marked Blake2b256 representing witness transaction IDs
    WTXID,
    Blake2b256
);

impl_hex_serde!(Blake2b256Digest);
impl_hex_serde!(TXID);
impl_hex_serde!(WTXID);

/// A Handshake Blake2b160Digest
pub type Blake2b160Digest = [u8; 20];

/// Hash data with blake2b160
pub fn blake2b160(preimage: &[u8]) -> Blake2b160Digest {
    let mut ctx = Blake2b::new(20);
    ctx.update(preimage);
    let digest = ctx.finalize();

    let mut result = Blake2b160Digest::default();
    result[..].copy_from_slice(digest.as_bytes());
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use coins_core::ser::ByteFormat;

    #[test]
    fn it_serializes_and_derializes_blake2b256digests() {
        let cases = [(
            TXID::default(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        )];
        for case in cases.iter() {
            let digest = TXID::deserialize_hex(case.1).unwrap();
            assert_eq!(digest.serialized_length(), 32);
            assert_eq!(digest, case.0);
            assert_eq!(digest.serialize_hex(), case.1);
            assert_eq!(case.0.serialize_hex(), case.1);
        }
    }
}
