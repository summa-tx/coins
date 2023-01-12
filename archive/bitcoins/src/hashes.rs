//! This module holds `MarkedDigest` types used by Bitcoin transactions. Currently we represent
//! only `TXID`s and `WTXID`s. In the future we may also represent sighash digests this way.

use coins_core::{hashes, impl_hex_serde, marked_digest};

marked_digest!(
    /// A marked Hash256Digest representing transaction IDs
    TXID,
    hashes::Hash256
);

marked_digest!(
    /// A marked Hash256Digest representing witness transaction IDs
    WTXID,
    hashes::Hash256
);

marked_digest!(
    /// A marked Hash256Digest representing a block hash
    BlockHash,
    hashes::Hash256
);

impl_hex_serde!(TXID);
impl_hex_serde!(WTXID);
impl_hex_serde!(BlockHash);

#[cfg(test)]
mod test {
    use super::*;
    use coins_core::ser::ByteFormat;

    #[test]
    fn it_serializes_and_derializes_hash256digests() {
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
