use crate::Bip32Error;

/// A simple hash function type signature
pub type HashFunc = dyn Fn(&[u8]) -> [u8; 32];

/// A Serializable 32-byte scalar
pub trait ScalarSerialize: std::marker::Sized {
    /// Serialize the scalar to an array
    fn to_array(&self) -> [u8; 32];

    /// Get a scalar from an array
    fn from_array(buf: [u8; 32]) -> Result<Self, Bip32Error>;
}

/// A serializable curve point
pub trait PointSerialize: std::marker::Sized {
    /// Serialize the pubkey
    fn to_array(&self) -> [u8; 33];

    /// Serialize the uncompressed pubkey
    fn to_array_uncompressed(&self) -> [u8; 65];

    /// Instantiate from a 33-byte uncompressed pubkey as a u8 array
    fn from_array(buf: [u8; 33]) -> Result<Self, Bip32Error>;

    /// Instantiate from a 65-byte compressed pubkey as a u8 array
    fn from_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error>;

    /// Serialize the raw pubkey (useful for Ethereum)
    fn to_array_raw(&self) -> [u8; 64] {
        let mut buf: [u8; 64] = [0u8; 64];
        buf.copy_from_slice(&self.to_array_uncompressed()[1..]);
        buf
    }

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
pub trait Secp256k1Backend<'a> {
    /// The underlying context type (if any)
    type Context;
    /// A Private Key
    type Privkey: ScalarSerialize + PartialEq + Clone;
    /// A Public Key
    type Pubkey: PointSerialize + PartialEq + Clone;
    /// A Signature
    type Signature;
    /// A Recoverage signature
    type RecoverableSignature;

    /// Instantiate a backend from a context. Useful for managing your own backend lifespan
    fn from_context(context: &'a Self::Context) -> Self;

    /// Init a backend, setting up any context necessary. This is implemented as a lazy_static
    /// context initialized on the first call. As such, the first call to init will be expensive,
    /// while successive calls will be cheap.
    fn init() -> Self;

    /// Derive a public key from a private key
    fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey;

    /// Add a scalar tweak to a public key. Returns a new key
    fn tweak_pubkey(&self, k: &Self::Pubkey, tweak: [u8; 32]) -> Result<Self::Pubkey, Bip32Error>;

    /// Add a scalar tweak to a private key. Returns a new key
    fn tweak_privkey(
        &self,
        k: &Self::Privkey,
        tweak: [u8; 32],
    ) -> Result<Self::Privkey, Bip32Error>;

    /// Sign a digest
    fn sign_digest(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::Signature;

    /// Sign a digest, and produce a recovery ID
    fn sign_digest_recoverable(
        &self,
        k: &Self::Privkey,
        digest: [u8; 32],
    ) -> Self::RecoverableSignature;

    /// Sign a message
    fn sign(&self, k: &Self::Privkey, message: &[u8], hash: &HashFunc) -> Self::Signature {
        self.sign_digest(k, hash(message))
    }

    /// Sign a message and produce a recovery ID
    fn sign_recoverable(
        &self,
        k: &Self::Privkey,
        message: &[u8],
        hash: &HashFunc,
    ) -> Self::RecoverableSignature {
        self.sign_digest_recoverable(k, hash(message))
    }

    /// Verify a signature on a digest
    fn verify_digest(
        &self,
        k: &Self::Pubkey,
        digest: [u8; 32],
        sig: &Self::Signature,
    ) -> Result<(), Bip32Error>;

    /// Verify a recoverable signature on a digest
    fn verify_digest_recoverable(
        &self,
        k: &Self::Pubkey,
        digest: [u8; 32],
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error>;

    /// Verify a signature on a message
    fn verify(
        &self,
        k: &Self::Pubkey,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::Signature,
    ) -> Result<(), Bip32Error> {
        self.verify_digest(k, hash(message), sig)
    }

    /// Sign a message and produce a recovery ID
    fn verify_recoverable(
        &self,
        k: &Self::Pubkey,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error> {
        self.verify_digest_recoverable(k, hash(message), sig)
    }
}

/// Contains a backend for performing operations on curve points. Uses libsecp256k1.
#[cfg(all(feature = "libsecp", not(feature = "rust_secp")))]
pub mod curve {
    // Wuille's secp
    use secp256k1;

    use super::{PointSerialize, ScalarSerialize, Secp256k1Backend};
    use crate::Bip32Error;

    lazy_static! {
        static ref CONTEXT: secp256k1::Secp256k1<secp256k1::All> = {
            secp256k1::Secp256k1::new()
        };
    }

    /// A Secp256k1Backend struct
    pub struct Secp256k1<'a>(&'a secp256k1::Secp256k1<secp256k1::All>);

    /// A Private Key
    #[derive(Debug)]
    pub struct Privkey(secp256k1::SecretKey);

    impl Clone for Privkey {
        fn clone(&self) -> Self {
            Self::from_array(self.to_array()).expect("Key must be valid")
        }
    }

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

        fn from_array(buf: [u8; 32]) -> Result<Self, Bip32Error> {
            Ok(secp256k1::SecretKey::from_slice(&buf)?.into())
        }
    }

    impl From<secp256k1::SecretKey> for Privkey {
        fn from(k: secp256k1::SecretKey) -> Self {
            Self(k)
        }
    }

    /// A Public Key
    #[derive(Debug)]
    pub struct Pubkey(secp256k1::PublicKey);

    impl Clone for Pubkey {
        fn clone(&self) -> Self {
            Self::from_array(self.to_array()).expect("Can't fail")
        }
    }

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

    impl<'a> Secp256k1Backend<'a> for Secp256k1<'a> {
        type Context = secp256k1::Secp256k1<secp256k1::All>;
        type Privkey = Privkey;
        type Pubkey = Pubkey;
        type Signature = secp256k1::Signature;
        type RecoverableSignature = secp256k1::recovery::RecoverableSignature;

        fn from_context(context: &'a secp256k1::Secp256k1<secp256k1::All>) -> Self {
            Self(context)
        }

        fn init() -> Self {
            Self(&CONTEXT)
        }

        fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey {
            secp256k1::PublicKey::from_secret_key(&self.0, &k.0).into()
        }

        fn tweak_pubkey(
            &self,
            k: &Self::Pubkey,
            tweak: [u8; 32],
        ) -> Result<Self::Pubkey, Bip32Error> {
            let mut key = k.0;
            key.add_exp_assign(&self.0, &tweak)?;
            Ok(key.into())
        }

        fn tweak_privkey(
            &self,
            k: &Self::Privkey,
            tweak: [u8; 32],
        ) -> Result<Self::Privkey, Bip32Error> {
            let mut key = k.0;
            key.add_assign(&tweak)?;
            Ok(key.into())
        }

        fn sign_digest(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::Signature {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            self.0.sign(&m, &k.0)
        }

        fn sign_digest_recoverable(
            &self,
            k: &Self::Privkey,
            digest: [u8; 32],
        ) -> Self::RecoverableSignature {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            self.0.sign_recoverable(&m, &k.0)
        }
        fn verify_digest(
            &self,
            k: &Self::Pubkey,
            digest: [u8; 32],
            sig: &Self::Signature,
        ) -> Result<(), Bip32Error> {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            Ok(self.0.verify(&m, sig, &k.0)?)
        }

        fn verify_digest_recoverable(
            &self,
            k: &Self::Pubkey,
            digest: [u8; 32],
            sig: &Self::RecoverableSignature,
        ) -> Result<(), Bip32Error> {
            let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
            Ok(self.0.verify(&m, &sig.to_standard(), &k.0)?)
        }
    }
}

/// Contains a backend for performing operations on curve points. Uses rust secp256k1.
#[cfg(all(feature = "rust_secp", not(feature = "libsecp")))]
pub mod curve {
    // Parity's secp
    use libsecp256k1 as secp256k1;

    use super::{PointSerialize, ScalarSerialize, Secp256k1Backend};
    use crate::Bip32Error;

    lazy_static! {
        static ref EC_MULT: Box<secp256k1::curve::ECMultContext> = {
            secp256k1::curve::ECMultContext::new_boxed()
        };
        static ref EC_MULT_GEN: Box<secp256k1::curve::ECMultGenContext> = {
            secp256k1::curve::ECMultGenContext::new_boxed()
        };
    }

    /// A Secp256k1Backend struct
    pub struct Secp256k1<'a>(
        &'a secp256k1::curve::ECMultContext,
        &'a secp256k1::curve::ECMultGenContext,
    );

    /// A Private Key
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Privkey(secp256k1::SecretKey);

    impl From<secp256k1::SecretKey> for Privkey {
        fn from(k: secp256k1::SecretKey) -> Self {
            Self(k)
        }
    }

    impl ScalarSerialize for Privkey {
        fn to_array(&self) -> [u8; 32] {
            self.0.serialize()
        }

        fn from_array(buf: [u8; 32]) -> Result<Self, Bip32Error> {
            Ok(secp256k1::SecretKey::parse(&buf)?.into())
        }
    }

    /// A Public Key
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Pubkey(secp256k1::PublicKey);

    impl From<secp256k1::PublicKey> for Pubkey {
        fn from(k: secp256k1::PublicKey) -> Self {
            Self(k)
        }
    }

    impl PointSerialize for Pubkey {
        fn to_array_uncompressed(&self) -> [u8; 65] {
            self.0.serialize()
        }

        fn to_array(&self) -> [u8; 33] {
            self.0.serialize_compressed()
        }

        fn from_array(buf: [u8; 33]) -> Result<Self, Bip32Error> {
            Ok(secp256k1::PublicKey::parse_compressed(&buf)?.into())
        }

        fn from_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error> {
            Ok(secp256k1::PublicKey::parse(&buf)?.into())
        }
    }

    /// A Signature with recovery information
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RecoverableSignature {
        /// The recovery id, `V`. Will always be `0..3u8`.
        pub recovery_id: secp256k1::RecoveryId,
        /// The non-recoverable `RS` signature
        pub sig: secp256k1::Signature,
    }

    impl<'a> Secp256k1Backend<'a> for Secp256k1<'a> {
        type Context = (
            &'a secp256k1::curve::ECMultContext,
            &'a secp256k1::curve::ECMultGenContext,
        );
        type Privkey = Privkey;
        type Pubkey = Pubkey;
        type Signature = secp256k1::Signature;
        type RecoverableSignature = RecoverableSignature;

        fn from_context(context: &'a Self::Context) -> Self {
            Self(context.0, context.1)
        }

        fn init() -> Self {
            Self(&EC_MULT, &EC_MULT_GEN)
        }

        fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey {
            secp256k1::PublicKey::from_secret_key_with_context(&k.0, self.1).into()
        }

        fn tweak_pubkey(
            &self,
            k: &Self::Pubkey,
            tweak: [u8; 32],
        ) -> Result<Self::Pubkey, Bip32Error> {
            let mut key = k.0.clone();
            key.tweak_add_assign_with_context(
                &secp256k1::SecretKey::parse(&tweak)?,
                self.0
            )?;
            Ok(key.into())
        }

        fn tweak_privkey(
            &self,
            k: &Self::Privkey,
            tweak: [u8; 32],
        ) -> Result<Self::Privkey, Bip32Error> {
            let mut key = k.0.clone();
            key.tweak_add_assign(&secp256k1::SecretKey::parse(&tweak)?)?;
            Ok(key.into())
        }

        fn sign_digest(&self, k: &Self::Privkey, digest: [u8; 32]) -> Self::Signature {
            self.sign_digest_recoverable(k, digest).sig
        }

        fn sign_digest_recoverable(
            &self,
            k: &Self::Privkey,
            digest: [u8; 32],
        ) -> Self::RecoverableSignature {
            let m = secp256k1::Message::parse(&digest);

            let sig = secp256k1::sign_with_context(
                &m,
                &k.0,
                self.1
            );
            RecoverableSignature{
                recovery_id: sig.1,
                sig: sig.0,
            }
        }
        fn verify_digest(
            &self,
            k: &Self::Pubkey,
            digest: [u8; 32],
            sig: &Self::Signature,
        ) -> Result<(), Bip32Error> {
            let m = secp256k1::Message::parse(&digest);
            let result = secp256k1::verify_with_context(
                &m,
                sig,
                &k.0,
                self.0);
            if result {
                Ok(())
            } else {
                Err(libsecp256k1_core::Error::InvalidSignature.into())
            }
        }

        fn verify_digest_recoverable(
            &self,
            k: &Self::Pubkey,
            digest: [u8; 32],
            sig: &Self::RecoverableSignature,
        ) -> Result<(), Bip32Error> {
            let m = secp256k1::Message::parse(&digest);
            let result = secp256k1::verify_with_context(
                &m,
                &sig.sig,
                &k.0,
                self.0);
            if result {
                Ok(())
            } else {
                Err(libsecp256k1_core::Error::InvalidSignature.into())
            }
        }
    }
}
