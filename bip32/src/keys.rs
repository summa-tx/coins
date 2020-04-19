use secp256k1::{self, Secp256k1};

use crate::{Bip32Error};

type HashFunc = dyn Fn(&[u8]) -> [u8; 32];

// TODO: consider how gen_context can be made more efficient on NONE arguments
/// A secp256k1 signing key
pub trait SigningKey: std::marker::Sized {
    /// Returns a new tweaked key. Unlike secp256k1, this does not modify in place.
    fn tweak_add(&self, other: [u8; 32]) -> Result<Self, Bip32Error>;

    /// Generate a signing context
    fn gen_context<C>() -> Secp256k1<C>
    where
        C: secp256k1::Signing
    {
        Secp256k1::gen_new()
    }

    /// Sign a digest
    fn sign_digest<C>(&self, context: Option<&Secp256k1<C>>, message: [u8; 32]) -> secp256k1::Signature
    where
        C: secp256k1::Signing;

    /// Sign a digest and produce a recovery ID
    fn sign_digest_recoverable<C>(&self, context: Option<&Secp256k1<C>>, message: [u8; 32]) -> secp256k1::recovery::RecoverableSignature
    where
        C: secp256k1::Signing;

    /// Sign a message
    fn sign<C>(&self, context: Option<&Secp256k1<C>>, message: &[u8], hash: &HashFunc) -> secp256k1::Signature
    where
        C: secp256k1::Signing
    {
        self.sign_digest(context, hash(message))
    }

    /// Sign a message and produce a recovery ID
    fn sign_recoverable<C>(&self, context: Option<&Secp256k1<C>>, message: &[u8], hash: &HashFunc) -> secp256k1::recovery::RecoverableSignature
    where
        C: secp256k1::Signing
    {
        self.sign_digest_recoverable(context, hash(message))
    }
}

/// A secp256k1 verifying key
pub trait VerifyingKey: std::marker::Sized {
    /// The corresponding signing key
    type SigningKey: SigningKey;

    /// Tweak with a 32-byte scalar. Unlike libsecp, this should return a new key
    fn tweak_add<C>(&self, context: Option<&Secp256k1<C>>, tweak: [u8; 32]) -> Result<Self, Bip32Error>
    where
        C: secp256k1::Verification;

    /// INstantiate `Self` from the corresponding signing key
    fn from_signing_key<C>(context: Option<&Secp256k1<C>>, key: &Self::SigningKey) -> Self
    where
        C: secp256k1::Signing;

    /// Generate a verifying context
    fn gen_context<C>() -> Secp256k1<C>
    where
        C: secp256k1::Verification
    {
        Secp256k1::gen_new()
    }

    /// Verify a signature on a digest
    fn verify_digest<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32], sig: &secp256k1::Signature) -> Result<(), Bip32Error>
    where
        C: secp256k1::Verification;

    /// Verify a recoverable signature on a digest.
    fn verify_digest_recoverable<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32], sig: &secp256k1::recovery::RecoverableSignature) -> Result<(), Bip32Error>
    where
        C: secp256k1::Verification
    {
        self.verify_digest(context, digest, &sig.to_standard())
    }

    /// Verify a signature on a message
    fn verify<C>(&self, context: Option<&Secp256k1<C>>, message: &[u8], hash: &HashFunc, sig: &secp256k1::Signature) -> Result<(), Bip32Error>
    where
        C: secp256k1::Verification
    {
        self.verify_digest(context, hash(message), sig)
    }

    /// Verify a recoverable signature on a message.
    fn verify_recoverable<C>(&self, context: Option<&Secp256k1<C>>, message: &[u8], hash: &HashFunc, sig: &secp256k1::recovery::RecoverableSignature) -> Result<(), Bip32Error>
    where
        C: secp256k1::Verification
    {
        self.verify(context, message, hash, &sig.to_standard())
    }
}

/// A Private Key
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Privkey(secp256k1::SecretKey);

impl Privkey {
    /// Serialize the pubkey
    pub fn serialize(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[..]);
        buf
    }

    /// INstantiate a privkey from an array
    pub fn from_array(buf: [u8; 32]) -> Self {
        Self(secp256k1::SecretKey::from_slice(&buf).expect("buf is 32 bytes"))
    }
}

impl SigningKey for Privkey {
    fn tweak_add(&self, other: [u8; 32]) -> Result<Self, Bip32Error> {
        let mut k = self.0.clone();
        k.add_assign(&other)?;
        Ok(Self(k))
    }

    fn sign_digest<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32]) -> secp256k1::Signature
    where
        C: secp256k1::Signing
    {
        let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
        match context {
            Some(c) => c.sign(&m, &self.0),
            None => Self::gen_context::<C>().sign(&m, &self.0)
        }
    }

    fn sign_digest_recoverable<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32]) -> secp256k1::recovery::RecoverableSignature
    where
        C: secp256k1::Signing
    {
        let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
        match context {
            Some(c) => c.sign_recoverable(&m, &self.0),
            None => Self::gen_context::<C>().sign_recoverable(&m, &self.0)
        }
    }
}

/// A Public Key
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Pubkey(secp256k1::PublicKey);

impl Pubkey {
    /// Serialize the uncompressed pubkey
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.0.serialize_uncompressed()
    }

    /// Serialize the raw pubkey (useful for Ethereum)
    pub fn serialize_raw(&self) -> [u8; 64] {
        let mut buf: [u8; 64] = [0u8; 64];
        buf.copy_from_slice(&self.serialize_uncompressed()[1..]);
        buf
    }

    /// Serialize the pubkey
    pub fn serialize(&self) -> [u8; 33] {
        self.0.serialize()
    }
}

impl VerifyingKey for Pubkey {
    type SigningKey = Privkey;

    fn tweak_add<C>(&self, context: Option<&Secp256k1<C>>, tweak: [u8; 32]) -> Result<Self, Bip32Error>
    where
        C: secp256k1::Verification
    {
        match context {
            Some(c) => {
                let mut k = self.0.clone();
                k.add_exp_assign(c, &tweak)?;
                Ok(Pubkey(k))
            },
            None => {
                let mut k = self.0.clone();
                k.add_exp_assign(&Self::gen_context::<C>(), &tweak)?;
                Ok(Pubkey(k))
            }
        }
    }

    fn from_signing_key<C>(context: Option<&Secp256k1<C>>, key: &Self::SigningKey) -> Self
    where
        C: secp256k1::Signing
    {

        match context {
            Some(c) => Pubkey(secp256k1::PublicKey::from_secret_key(c, &key.0)),
            None => Pubkey(secp256k1::PublicKey::from_secret_key(&Self::SigningKey::gen_context::<C>(), &key.0))
        }
    }

    fn verify_digest<C>(&self, context: Option<&Secp256k1<C>>, digest: [u8; 32], sig: &secp256k1::Signature) -> Result<(), Bip32Error>
    where
        C: secp256k1::Verification
    {
        let m = secp256k1::Message::from_slice(&digest).expect("digest is 32 bytes");
        match context {
            Some(c) => Ok(c.verify(&m, sig, &self.0)?),
            None => Ok(Self::gen_context::<C>().verify(&m, sig, &self.0)?)
        }
    }
}
