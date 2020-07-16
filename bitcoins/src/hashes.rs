//! This module holds `MarkedDigest` types used by Bitcoin transactions. Currently we represent
//! only `TXID`s and `WTXID`s. In the future we may also represent sighash digests this way.

use bitcoin_spv::types::Hash256Digest;

use coins_core::hashes::marked::MarkedDigest;

mark_hash256!(
    /// A marked Hash256Digest representing transaction IDs
    TXID
);
mark_hash256!(
    /// A marked Hash256Digest representing witness transaction IDs
    WTXID
);

mark_hash256!(
    /// A marked Hash256Digest representing witness transaction IDs
    BlockHash
);

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
