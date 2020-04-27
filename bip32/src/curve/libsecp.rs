// Wuille's secp
use secp256k1;

use crate::{Bip32Error, curve::{model::*}};

pub(crate) type Error = secp256k1::Error;

lazy_static! {
    static ref CONTEXT: secp256k1::Secp256k1<secp256k1::All> = { secp256k1::Secp256k1::new() };
}

/// A Secp256k1Backend struct
pub struct Secp256k1<'a>(&'a secp256k1::Secp256k1<secp256k1::All>);

/// A Private Key
#[derive(Debug)]
pub struct Privkey(secp256k1::SecretKey);

impl Clone for Privkey {
    fn clone(&self) -> Self {
        Self::from_privkey_array(self.privkey_array()).expect("Key must be valid")
    }
}

impl std::cmp::Eq for Privkey {}

impl std::cmp::PartialEq for Privkey {
    fn eq(&self, other: &Self) -> bool {
        self.privkey_array() == other.privkey_array()
    }
}

impl ScalarSerialize for Privkey {
    fn privkey_array(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[..32]);
        buf
    }
}

impl ScalarDeserialize for Privkey {
    fn from_privkey_array(buf: [u8; 32]) -> Result<Self, Bip32Error> {
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
        Self::from_pubkey_array(self.pubkey_array()).expect("Key must be valid")
    }
}

impl std::cmp::Eq for Pubkey {}

impl std::cmp::PartialEq for Pubkey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey_array()[..] == other.pubkey_array()[..]
    }
}

impl From<secp256k1::PublicKey> for Pubkey {
    fn from(k: secp256k1::PublicKey) -> Self {
        Self(k)
    }
}

impl PointSerialize for Pubkey {
    fn pubkey_array(&self) -> [u8; 33] {
        self.0.serialize()
    }

    fn pubkey_array_uncompressed(&self) -> [u8; 65] {
        self.0.serialize_uncompressed()
    }
}

impl PointDeserialize for Pubkey {
    fn from_pubkey_array(buf: [u8; 33]) -> Result<Self, Bip32Error> {
        Ok(secp256k1::PublicKey::from_slice(&buf)?.into())
    }

    fn from_pubkey_array_uncompressed(buf: [u8; 65]) -> Result<Self, Bip32Error> {
        Ok(secp256k1::PublicKey::from_slice(&buf)?.into())
    }
}

/// Type alias for underlyin signature type
pub type Signature = secp256k1::Signature;

impl SigSerialize for secp256k1::Signature {
    fn to_der(&self) -> Vec<u8> {
        secp256k1::Signature::serialize_der(self).to_vec()
    }

    fn try_from_der(der: &[u8]) -> Result<Self, Bip32Error> {
        Ok(Self::from_der(der)?)
    }
}

impl SigSerialize for secp256k1::recovery::RecoverableSignature {
    fn to_der(&self) -> Vec<u8> {
        self.without_recovery().to_der()
    }

    fn try_from_der(_der: &[u8]) -> Result<Self, Bip32Error> {
        Err(Bip32Error::NoRecoveryID)
    }
}

/// Type alias for underlyin RecoverableSigSerialize signature type
pub type RecoverableSignature = secp256k1::recovery::RecoverableSignature;

/// A serializable RecoverableSignature
impl RecoverableSigSerialize for secp256k1::recovery::RecoverableSignature {
    type Signature = secp256k1::Signature;

    fn serialize_vrs(&self) -> (u8, [u8; 32], [u8; 32]) {
        let (rec_id, sig) = self.serialize_compact();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        (rec_id.to_i32() as u8, r, s)
    }

    fn deserialize_vrs(vrs: (u8, [u8; 32], [u8; 32])) -> Result<Self, Bip32Error> {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&vrs.1);
        data[32..].copy_from_slice(&vrs.2);
        let rec_id = secp256k1::recovery::RecoveryId::from_i32(vrs.0 as i32)?;
        Ok(Self::from_compact(&data, rec_id)?)
    }

    fn without_recovery(&self) -> Self::Signature {
        // full disambiguation
        secp256k1::recovery::RecoverableSignature::to_standard(self)
    }
}

impl<'a> Secp256k1Backend<'a> for Secp256k1<'a> {
    type Error = Bip32Error;
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
