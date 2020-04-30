/// The backend model
pub mod model;

/// Contains a backend for performing operations on curve points. Uses libsecp256k1.
#[cfg(all(feature = "libsecp", not(feature = "rust-secp")))]
pub mod libsecp;

/// Contains a backend for performing operations on curve points. Uses rust secp256k1.
#[cfg(all(feature = "rust-secp", not(feature = "libsecp")))]
pub mod rust_secp;

pub use model::*;

#[cfg(all(feature = "rust-secp", not(feature = "libsecp")))]
pub use rust_secp as backend;

#[cfg(all(feature = "libsecp", not(feature = "rust-secp")))]
pub use libsecp as backend;

#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub use backend::*;


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_serializes_and_deserializes_affines() {
        let backend = Secp256k1::init();
        let privkey = Privkey::from_privkey_array([2u8; 32]).unwrap();
        let pubkey = backend.derive_pubkey(&privkey);

        let pk_bytes = pubkey.pubkey_array_uncompressed();
        let deser = Pubkey::from_pubkey_array_uncompressed(pk_bytes).unwrap();
        assert_eq!(deser, pubkey);

        let pk_bytes = pubkey.pubkey_array();
        let deser = Pubkey::from_pubkey_array(pk_bytes).unwrap();
        assert_eq!(deser, pubkey);
    }
}
