use bitcoin_spv::btcspv::hash256;

use crate::Bip32Error;

/// A simple hash function type signature
pub type HashFunc = dyn Fn(&[u8]) -> [u8; 32];

/// A Serializable 32-byte scalar
pub trait ScalarSerialize {
    /// Serialize the scalar to an array
    fn privkey_array(&self) -> [u8; 32];
}

/// A deserializable 32-byte scalar
pub trait ScalarDeserialize: std::marker::Sized {
    /// Get a scalar from an array
    fn from_privkey_array(buf: [u8; 32]) -> Result<Self, Bip32Error>;
}

/// A serializable curve point
pub trait PointSerialize {
    /// Serialize the pubkey
    fn pubkey_array(&self) -> [u8; 33];

    /// Serialize the uncompressed pubkey
    fn pubkey_array_uncompressed(&self) -> [u8; 65];

    /// Serialize the raw pubkey (useful for Ethereum)
    fn pubkey_array_raw(&self) -> [u8; 64] {
        let mut buf: [u8; 64] = [0u8; 64];
        buf.copy_from_slice(&self.pubkey_array_uncompressed()[1..]);
        buf
    }
}

/// A deserializable curve point
pub trait PointDeserialize: std::marker::Sized {
    /// Instantiate from a 33-byte uncompressed pubkey as a u8 array
    fn from_pubkey_array(buf: [u8; 33]) -> Result<Self, Bip32Error>;

    /// Instantiate from a 65-byte compressed pubkey as a u8 array
    fn from_pubkey_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error>;

    /// Instantiate from a 64-byte raw pubkey as a u8 array
    fn from_pubkey_array_raw(buf: [u8; 64]) -> Result<Self, Bip32Error> {
        let mut raw = [4u8; 65];
        raw[1..].copy_from_slice(&buf);
        Self::from_pubkey_array_uncompressed(raw)
    }
}

/// A secp256k1 signing key
pub trait SigningKey: std::marker::Sized + ScalarSerialize {
    /// The corresponding verifying key
    type VerifyingKey: VerifyingKey<
        Signature = Self::Signature,
        RecoverableSignature = Self::RecoverableSignature,
    >;

    /// The signature produced
    type Signature: SigSerialize;

    /// The recoverable signature produced
    type RecoverableSignature: RecoverableSigSerialize<Signature = Self::Signature>;

    /// Derive the corresponding pubkey
    fn to_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error>;

    /// Sign a digest
    fn sign_digest(&self, digest: [u8; 32]) -> Result<Self::Signature, Bip32Error>;

    /// Sign a digest and produce a recovery ID
    fn sign_digest_recoverable(
        &self,
        digest: [u8; 32],
    ) -> Result<Self::RecoverableSignature, Bip32Error>;

    /// Sign a message
    fn sign_with_hash(
        &self,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<Self::Signature, Bip32Error> {
        self.sign_digest(hash(message))
    }

    /// Sign a message and produce a recovery ID
    fn sign_recoverable_with_hash(
        &self,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<Self::RecoverableSignature, Bip32Error> {
        self.sign_digest_recoverable(hash(message))
    }

    /// Produce a signature on `sha2(sha2(message))`
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Bip32Error> {
        self.sign_with_hash(message, &|m| hash256(&[m]))
    }

    /// Produce a recoverable signature on `sha2(sha2(message))`
    fn sign_recoverable(&self, message: &[u8]) -> Result<Self::RecoverableSignature, Bip32Error> {
        self.sign_recoverable_with_hash(message, &|m| hash256(&[m]))
    }
}

/// A secp256k1 verifying key
pub trait VerifyingKey: std::marker::Sized + PointSerialize {
    /// The corresponding signing key
    type SigningKey: SigningKey<
        Signature = Self::Signature,
        RecoverableSignature = Self::RecoverableSignature,
    >;

    /// The signature verified
    type Signature: SigSerialize;

    /// The recoverable signature verified
    type RecoverableSignature: RecoverableSigSerialize<Signature = Self::Signature>;

    /// Instantiate `Self` from the corresponding signing key
    fn from_signing_key(key: &Self::SigningKey) -> Result<Self, Bip32Error>;

    /// Verify a signature on a digest
    fn verify_digest(&self, digest: [u8; 32], sig: &Self::Signature) -> Result<(), Bip32Error>;

    /// Verify a recoverable signature on a digest.
    fn verify_digest_recoverable(
        &self,
        digest: [u8; 32],
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error> {
        self.verify_digest(digest, &sig.without_recovery())
    }

    /// Verify a signature on a message
    fn verify_with_hash(
        &self,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::Signature,
    ) -> Result<(), Bip32Error> {
        self.verify_digest(hash(message), sig)
    }

    /// Verify a recoverable signature on a message.
    fn verify_recoverable_with_hash(
        &self,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error> {
        self.verify_digest(hash(message), &sig.without_recovery())
    }

    /// Produce a signature on `sha2(sha2(message))`
    fn verify(&self, message: &[u8], sig: &Self::Signature) -> Result<(), Bip32Error> {
        self.verify_with_hash(message, &|m| hash256(&[m]), sig)
    }

    /// Produce a recoverable signature on `sha2(sha2(message))`
    fn verify_recoverable(
        &self,
        message: &[u8],
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error> {
        self.verify_recoverable_with_hash(message, &|m| hash256(&[m]), sig)
    }
}

/// A Serializable Signature
pub trait SigSerialize: Clone {
    /// Serialize to DER
    fn to_der(&self) -> Vec<u8>;

    /// Deserialize from DER
    fn try_from_der(der: &[u8]) -> Result<Self, Bip32Error>;
}

/// A serializable RecoverableSignature
pub trait RecoverableSigSerialize: SigSerialize {
    /// A non-recoverable signature type
    type Signature: SigSerialize;

    /// Serialize to VRS tuple
    fn serialize_vrs(&self) -> (u8, [u8; 32], [u8; 32]);

    /// Deserialize a recoverable signature from a VRS tuple
    fn deserialize_vrs(vrs: (u8, [u8; 32], [u8; 32])) -> Result<Self, Bip32Error>;

    /// Clone, and convert into a standard sig.
    fn without_recovery(&self) -> Self::Signature;
}

/// A minmial curve-math backend interface
pub trait Secp256k1Backend<'a> {
    /// An associated error type that can be converted into the crate's error type
    type Error: std::error::Error + Into<Bip32Error>;
    /// The underlying context type (if any)
    type Context;
    /// A Private Key
    type Privkey: ScalarSerialize + ScalarDeserialize + PartialEq + Clone;
    /// A Public Key
    type Pubkey: PointSerialize + PointDeserialize + PartialEq + Clone;
    /// A Signature
    type Signature: SigSerialize;
    /// A Recoverage signature
    type RecoverableSignature: RecoverableSigSerialize<Signature = Self::Signature>;

    /// Instantiate a backend from a context. Useful for managing your own backend lifespan
    fn from_context(context: &'a Self::Context) -> Self;

    /// Init a backend, setting up any context necessary. This is implemented as a lazy_static
    /// context initialized on the first call. As such, the first call to init will be expensive,
    /// while successive calls will be cheap.
    fn init() -> Self;

    /// Derive a public key from a private key
    fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey;

    /// Add a scalar tweak to a public key. Returns a new key
    fn tweak_pubkey(&self, k: &Self::Pubkey, tweak: [u8; 32]) -> Result<Self::Pubkey, Self::Error>;

    /// Add a scalar tweak to a private key. Returns a new key
    fn tweak_privkey(
        &self,
        k: &Self::Privkey,
        tweak: [u8; 32],
    ) -> Result<Self::Privkey, Self::Error>;

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
    ) -> Result<(), Self::Error>;

    /// Verify a recoverable signature on a digest
    fn verify_digest_recoverable(
        &self,
        k: &Self::Pubkey,
        digest: [u8; 32],
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Self::Error>;

    /// Verify a signature on a message
    fn verify(
        &self,
        k: &Self::Pubkey,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::Signature,
    ) -> Result<(), Self::Error> {
        self.verify_digest(k, hash(message), sig)
    }

    /// Sign a message and produce a recovery ID
    fn verify_recoverable(
        &self,
        k: &Self::Pubkey,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Self::Error> {
        self.verify_digest_recoverable(k, hash(message), sig)
    }
}
