/// The backend model. Contains the `Secp256k1Backend` trait, and related traits.
pub mod model;

/// Contains a backend for performing operations on curve points. Uses libsecp256k1.
#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub mod libsecp;

/// Contains a backend for performing operations on curve points. Uses rust secp256k1.
#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub mod rust_secp;

pub use model::*;

#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub use libsecp as backend;

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub use rust_secp as backend;

#[doc(hidden)]
pub use backend::*;

pub use backend::Secp256k1;

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
