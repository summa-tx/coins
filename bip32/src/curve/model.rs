use bitcoin_spv::{
    btcspv::hash160,
    types::{Hash160Digest, Hash256Digest},
};

use crate::{primitives::KeyFingerprint, Bip32Error, hashes::blake2b160};

/// A simple hash function type signature
pub type HashFunc = dyn Fn(&[u8]) -> Hash256Digest;

/// A Serializable 32-byte scalar
pub trait ScalarSerialize {
    /// Serialize the scalar to an array
    fn privkey_array(&self) -> [u8; 32];

    /// The first four bytes of the hash160 of the private key scalar
    ///
    /// TODO: replace this later when underlying libs have safe debugging
    fn short_id(&self) -> [u8; 4] {
        let digest = hash160(&self.privkey_array());
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&digest.as_ref()[..4]);
        buf
    }
}

/// A deserializable 32-byte scalar
pub trait ScalarDeserialize: std::marker::Sized + std::fmt::Debug {
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

    /// Calculate the key fingerprint of the associated public key. This is the first 4 bytes of
    /// the Bitcoin HASH_160 of the compressed representation of the public key.
    fn fingerprint(&self) -> KeyFingerprint {
        let digest = hash160(&self.pubkey_array());
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&digest.as_ref()[..4]);
        buf.into()
    }

    /// Calculate the hash160 of the associated public key. This is commonly used to consturct
    /// pubkeyhash outputs in bitcoin-like chains, and has been provided here as a convenience.
    fn hash160(&self) -> Hash160Digest {
        hash160(&self.pubkey_array())
    }

    fn blake2b160(&self) -> [u8; 20] {
        blake2b160(&self.pubkey_array())
    }
}

/// A deserializable curve point
pub trait PointDeserialize: std::marker::Sized + std::fmt::Debug {
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

/// A Serializable Signature
pub trait SigSerialize: Clone + std::fmt::Debug {
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
pub trait Secp256k1Backend: Clone + std::fmt::Debug + PartialEq {
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
    fn sign_digest(&self, k: &Self::Privkey, digest: Hash256Digest) -> Self::Signature;

    /// Sign a digest, and produce a recovery ID
    fn sign_digest_recoverable(
        &self,
        k: &Self::Privkey,
        digest: Hash256Digest,
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

    /// Verify a signature on a digest.
    ///
    /// *Warning* it is NOT SECURE to use this function without also verifying the method by which
    /// the digest was produced. Doing so can result in forgery attacks.
    fn verify_digest(
        &self,
        k: &Self::Pubkey,
        digest: Hash256Digest,
        sig: &Self::Signature,
    ) -> Result<(), Self::Error>;

    /// Verify a recoverable signature on a digest
    ///
    /// *Warning* it is NOT SECURE to use this function without also verifying the method by which
    /// the digest was produced. Doing so can result in forgery attacks.
    fn verify_digest_recoverable(
        &self,
        k: &Self::Pubkey,
        digest: Hash256Digest,
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

    /// Recover the public key that produced a `RecoverableSignature` on a certain digest.
    fn recover_pubkey(
        &self,
        digest: Hash256Digest,
        sig: &Self::RecoverableSignature,
    ) -> Result<Self::Pubkey, Self::Error>;
}
