use crate::{Bip32Error};

/// A simple hash function type signature
pub type HashFunc = dyn Fn(&[u8]) -> [u8; 32];

/// A Serializable 32-byte scalar
pub trait ScalarSerialize: std::marker::Sized {
    /// Serialize the scalar to an array
    fn to_array(&self) -> [u8; 32];

    /// Get a scalar from an array
    fn from_array(buf: [u8; 32]) -> Self;
}

/// A serializable curve point
pub trait PointSerialize: std::marker::Sized {
    /// Serialize the uncompressed pubkey
    fn to_array_uncompressed(&self) -> [u8; 65];

    /// Serialize the raw pubkey (useful for Ethereum)
    fn to_array_raw(&self) -> [u8; 64] {
        let mut buf: [u8; 64] = [0u8; 64];
        buf.copy_from_slice(&self.to_array_uncompressed()[1..]);
        buf
    }

    /// Serialize the pubkey
    fn to_array(&self) -> [u8; 33];

    /// Instantiate from a 33-byte uncompressed pubkey as a u8 array
    fn from_array(buf: [u8; 33]) -> Result<Self, Bip32Error>;

    /// Instantiate from a 65-byte compressed pubkey as a u8 array
    fn from_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error>;

    /// Instantiate from a 64-byte raw pubkey as a u8 array
    fn from_array_raw(buf: [u8; 64]) -> Result<Self, Bip32Error> {
        let mut raw = [4u8; 65];
        raw[1..].copy_from_slice(&buf);
        PointSerialize::from_array_uncompressed(raw)
    }
}

/// A Serializable Signature
pub trait SigSerialize {
    /// Serialize to DER
    fn serialize_der(&self) -> Vec<u8>;
}

/// A serializable RecoverableSignature
pub trait RecoverableSigSerialize: SigSerialize {
    /// Serialize to VRS tuple
    fn serialize_vrs(&self) -> (u8, [u8; 32], [u8; 32]);
}

/// A minmial curve-math backend interface
pub trait Secp256k1Backend {
    /// A Private Key
    type Privkey: ScalarSerialize + PartialEq;
    /// A Public Key
    type Pubkey: PointSerialize + PartialEq;
    /// A Signature
    type Signature;
    /// A Recoverage signature
    type RecoverableSignature;

    /// Init a backend, setting up any context necessary
    fn init() -> Self;

    /// Derive a public key from a private key
    fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey;

    /// Add a scalar tweak to a public key. Returns a new key
    fn tweak_pubkey(&self, k: &Self::Pubkey, tweak: [u8; 32]) -> Result<Self::Pubkey, Bip32Error>;

    /// Add a scalar tweak to a private key. Returns a new key
    fn tweak_privkey(&self, k: &Self::Privkey, tweak: [u8; 32]) -> Result<Self::Privkey, Bip32Error>;

    /// Sign a digest
    fn sign_digest(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::Signature;

    /// Sign a digest, and produce a recovery ID
    fn sign_digest_recoverable(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::RecoverableSignature;

    /// Sign a message
    fn sign(&self, k: &Self::Privkey, message: &[u8], hash: &HashFunc) -> Self::Signature {
        self.sign_digest(k, hash(message))
    }

    /// Sign a message and produce a recovery ID
    fn sign_recoverable(&self, k: &Self::Privkey, message: &[u8], hash: &HashFunc) -> Self::RecoverableSignature {
        self.sign_digest_recoverable(k, hash(message))
    }

    /// Verify a signature on a digest
    fn verify_digest(&self, k: &Self::Pubkey, digest: [u8; 32], sig: &Self::Signature) -> Result<(), Bip32Error>;

    /// Verify a recoverable signature on a digest
    fn verify_digest_recoverable(&self, k: &Self::Pubkey, digest: [u8; 32], sig: &Self::RecoverableSignature) -> Result<(), Bip32Error>;

    /// Verify a signature on a message
    fn verify(&self, k: &Self::Pubkey, message: &[u8], hash: &HashFunc, sig: &Self::Signature) -> Result<(), Bip32Error> {
        self.verify_digest(k, hash(message), sig)
    }

    /// Sign a message and produce a recovery ID
    fn verify_recoverable(&self, k: &Self::Pubkey, message: &[u8], hash: &HashFunc, sig: &Self::RecoverableSignature) -> Result<(), Bip32Error> {
        self.verify_digest_recoverable(k, hash(message), sig)
    }

}

/// Contains a backend for performing operations on curve points
#[cfg(feature = "libsecp")]
pub mod curve {
    use secp256k1;

    use crate::Bip32Error;
    use super::{Secp256k1Backend, PointSerialize, ScalarSerialize};

    /// A Secp256k1Backend struct
    pub struct Secp256k1(secp256k1::Secp256k1<secp256k1::All>);

    /// A Private Key
    #[derive(Debug, Clone)]
    pub struct Privkey(secp256k1::SecretKey);

    impl std::cmp::Eq for Privkey {}

    impl std::cmp::PartialEq for Privkey {
        fn eq(&self, other: &Self) -> bool {
            self.to_array() == other.to_array()
        }
    }

    impl ScalarSerialize for Privkey {
        fn to_array(&self) -> [u8; 32] {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&self.0[..32]);
            buf
        }

        fn from_array(buf: [u8; 32]) -> Self {
            secp256k1::SecretKey::from_slice(&buf).expect("buf is 32 bytes").into()
        }
    }

    impl From<secp256k1::SecretKey> for Privkey {
        fn from(k: secp256k1::SecretKey) -> Self {
            Self(k)
        }
    }

    /// A Public Key
    #[derive(Debug, Clone)]
    pub struct Pubkey(secp256k1::PublicKey);

    impl std::cmp::Eq for Pubkey {}

    impl std::cmp::PartialEq for Pubkey {
        fn eq(&self, other: &Self) -> bool {
            self.to_array()[..] == other.to_array()[..]
        }
    }

    impl From<secp256k1::PublicKey> for Pubkey {
        fn from(k: secp256k1::PublicKey) -> Self {
            Self(k)
        }
    }

    impl PointSerialize for Pubkey {
        fn to_array_uncompressed(&self) -> [u8; 65] {
            self.0.serialize_uncompressed()
        }

        fn to_array(&self) -> [u8; 33] {
            self.0.serialize()
        }

        fn from_array(buf: [u8; 33]) -> Result<Self, Bip32Error> {
            Ok(secp256k1::PublicKey::from_slice(&buf)?.into())
        }

        fn from_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error> {
            Ok(secp256k1::PublicKey::from_slice(&buf)?.into())
        }
    }

    impl Secp256k1Backend for Secp256k1 {
        type Privkey = Privkey;
        type Pubkey = Pubkey;
        type Signature = secp256k1::Signature;
        type RecoverableSignature = secp256k1::recovery::RecoverableSignature;

        fn init() -> Self {
            Self(secp256k1::Secp256k1::new())
        }

        fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey {
            secp256k1::PublicKey::from_secret_key(&self.0, &k.0).into()
        }

        fn tweak_pubkey(&self, k: &Self::Pubkey, tweak: [u8; 32]) -> Result<Self::Pubkey , Bip32Error>{
            let mut key = k.0;
            key.add_exp_assign(&self.0, &tweak)?;
            Ok(key.into())

        }

        fn tweak_privkey(&self, k: &Self::Privkey, tweak: [u8; 32]) -> Result<Self::Privkey , Bip32Error>{
            let mut key = k.0;
            key.add_assign(&tweak)?;
            Ok(key.into())
        }

        fn sign_digest(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::Signature {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            self.0.sign(&m, &k.0)
        }

        fn sign_digest_recoverable(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::RecoverableSignature {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            self.0.sign_recoverable(&m, &k.0)
        }
        fn verify_digest(&self, k: &Self::Pubkey, digest: [u8; 32], sig: &Self::Signature) -> Result<(), Bip32Error> {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            Ok(self.0.verify(&m, sig, &k.0)?)
        }

        fn verify_digest_recoverable(&self, k: &Self::Pubkey, digest: [u8; 32], sig: &Self::RecoverableSignature) -> Result<(), Bip32Error> {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            Ok(self.0.verify(&m, &sig.to_standard(), &k.0)?)
        }
    }
}

// #[cfg(feature = "rust_secp")]
// pub mod curve {
//
// }
