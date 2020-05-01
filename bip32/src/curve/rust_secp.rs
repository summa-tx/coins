// Parity's secp
use libsecp256k1 as secp256k1;

use crate::{curve::model::*, Bip32Error};

pub(crate) type Error = libsecp256k1_core::Error;

#[cfg(not(feature = "rust-secp-static-context"))]
lazy_static! {
    static ref EC_MULT: Box<secp256k1::curve::ECMultContext> =
        { secp256k1::curve::ECMultContext::new_boxed() };
    static ref EC_MULT_GEN: Box<secp256k1::curve::ECMultGenContext> =
        { secp256k1::curve::ECMultGenContext::new_boxed() };
}

/// A Secp256k1Backend struct using the Parity Rust implementation of Secp256k1.
pub struct Secp256k1<'a>(
    &'a secp256k1::curve::ECMultContext,
    &'a secp256k1::curve::ECMultGenContext,
);

impl<'a> Secp256k1<'a> {
    /// Instantiate a backend from a context. Useful for managing your own backend lifespan
    pub fn from_context(context: &'a Self::Context) -> Self {
        Self(context.0, context.1)
    }

    /// Init a backend, setting up any context necessary. This is implemented as a lazy_static
    /// context initialized on the first call. As such, the first call to init will be expensive,
    /// while successive calls will be cheap.
    #[cfg(feature = "rust-secp-static-context")]
    pub fn init() -> Self {
        Self(&secp256k1::ECMULT_CONTEXT, &secp256k1::ECMULT_GEN_CONTEXT)
    }

    /// Init a backend, setting up any context necessary. This is implemented as a lazy_static
    /// context initialized on the first call. As such, the first call to init will be expensive,
    /// while successive calls will be cheap.
    #[cfg(not(feature = "rust-secp-static-context"))]
    pub fn init() -> Self {
        Self(&EC_MULT, &EC_MULT_GEN)
    }

}


/// A Private Key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privkey(secp256k1::SecretKey);

impl From<secp256k1::SecretKey> for Privkey {
    fn from(k: secp256k1::SecretKey) -> Self {
        Self(k)
    }
}

impl ScalarSerialize for Privkey {
    fn privkey_array(&self) -> [u8; 32] {
        self.0.serialize()
    }
}

impl ScalarDeserialize for Privkey {
    fn from_privkey_array(buf: [u8; 32]) -> Result<Self, Bip32Error> {
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
    fn pubkey_array_uncompressed(&self) -> [u8; 65] {
        self.0.serialize()
    }

    fn pubkey_array(&self) -> [u8; 33] {
        self.0.serialize_compressed()
    }
}

impl PointDeserialize for Pubkey {
    fn from_pubkey_array(buf: [u8; 33]) -> Result<Self, Bip32Error> {
        Ok(secp256k1::PublicKey::parse_compressed(&buf)?.into())
    }

    fn from_pubkey_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error> {
        Ok(secp256k1::PublicKey::parse(&buf)?.into())
    }
}

/// Type alias for the underlying Signature type
pub type Signature = secp256k1::Signature;

/// A Signature with recovery information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// The recovery id, `V`. Will always be `0..3u8`.
    pub recovery_id: secp256k1::RecoveryId,
    /// The non-recoverable `RS` signature
    pub sig: secp256k1::Signature,
}

impl SigSerialize for secp256k1::Signature {
    fn to_der(&self) -> Vec<u8> {
        secp256k1::Signature::serialize_der(self).as_ref().to_vec()
    }

    fn try_from_der(der: &[u8]) -> Result<Self, Bip32Error> {
        Ok(Self::parse_der(der)?)
    }
}

impl SigSerialize for RecoverableSignature {
    fn to_der(&self) -> Vec<u8> {
        self.sig.serialize_der().as_ref().to_vec()
    }

    fn try_from_der(_der: &[u8]) -> Result<Self, Bip32Error> {
        Err(Bip32Error::NoRecoveryID)
    }
}

/// A serializable RecoverableSignature
impl RecoverableSigSerialize for RecoverableSignature {
    type Signature = secp256k1::Signature;

    fn serialize_vrs(&self) -> (u8, [u8; 32], [u8; 32]) {
        let sig = self.sig.serialize();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        (self.recovery_id.serialize(), r, s)
    }

    fn deserialize_vrs(vrs: (u8, [u8; 32], [u8; 32])) -> Result<Self, Bip32Error> {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&vrs.1);
        data[32..].copy_from_slice(&vrs.2);
        let sig = secp256k1::Signature::parse(&data);
        Ok(Self {
            recovery_id: secp256k1::RecoveryId::parse(vrs.0)?,
            sig,
        })
    }

    fn without_recovery(&self) -> Self::Signature {
        self.sig.clone()
    }
}

impl Clone for Secp256k1<'_> {
    fn clone(&self) -> Self {
        Secp256k1(self.0, self.1)
    }
}

impl std::cmp::PartialEq for Secp256k1<'_> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl std::fmt::Debug for Secp256k1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secp256k1Backend: libsecp bindings")
    }
}

impl<'a> Secp256k1Backend<'a> for Secp256k1<'a> {
    type Error = Bip32Error;
    type Context = (
        &'a secp256k1::curve::ECMultContext,
        &'a secp256k1::curve::ECMultGenContext,
    );
    type Privkey = Privkey;
    type Pubkey = Pubkey;
    type Signature = secp256k1::Signature;
    type RecoverableSignature = RecoverableSignature;

    fn derive_pubkey(&self, k: &Self::Privkey) -> Self::Pubkey {
        secp256k1::PublicKey::from_secret_key_with_context(&k.0, self.1).into()
    }

    fn tweak_pubkey(&self, k: &Self::Pubkey, tweak: [u8; 32]) -> Result<Self::Pubkey, Bip32Error> {
        let mut key = k.0.clone();
        key.tweak_add_assign_with_context(&secp256k1::SecretKey::parse(&tweak)?, self.0)?;
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

        let sig = secp256k1::sign_with_context(&m, &k.0, self.1);
        RecoverableSignature {
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
        let result = secp256k1::verify_with_context(&m, sig, &k.0, self.0);
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
        let result = secp256k1::verify_with_context(&m, &sig.sig, &k.0, self.0);
        if result {
            Ok(())
        } else {
            Err(libsecp256k1_core::Error::InvalidSignature.into())
        }
    }

    fn recover_pubkey(&self, digest: [u8; 32], sig: &Self::RecoverableSignature) -> Result<Self::Pubkey, Bip32Error> {
        let m = secp256k1::Message::parse(&digest);
        Ok(secp256k1::recover_with_context(&m, &sig.sig, &sig.recovery_id, self.0)?.into())
    }
}
