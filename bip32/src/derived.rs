use crate::{
    path::KeyDerivation,
    model::{RecoverableSigSerialize, SigningKey, SigSerialize, VerifyingKey},
    xkeys::{ChainCode, KeyFingerprint, Hint, XKey},
    Bip32Error,
};

#[doc(hidden)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DerivedKey<T> {
    /// A key coupled with its derivation
    pub key: T,
    pub derivation: KeyDerivation,
}

impl<T> From<(T, KeyDerivation)> for DerivedKey<T> {
    fn from(tuple: (T, KeyDerivation)) -> Self {
        Self {
            key: tuple.0,
            derivation: tuple.1,
        }
    }
}

impl<'a, T> XKey for DerivedKey<T>
where
    T: XKey,
{
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error> {
        self.key.fingerprint()
    }

    fn depth(&self) -> u8 {
        self.key.depth()
    }
    fn set_depth(&mut self, depth: u8) {
        self.key.set_depth(depth)
    }
    fn parent(&self) -> KeyFingerprint {
        self.key.parent()
    }
    fn set_parent(&mut self, parent: KeyFingerprint) {
        self.key.set_parent(parent)
    }
    fn index(&self) -> u32 {
        self.key.index()
    }
    fn set_index(&mut self, index: u32) {
        self.key.set_index(index)
    }
    fn chain_code(&self) -> ChainCode {
        self.key.chain_code()
    }
    fn set_chain_code(&mut self, chain_code: ChainCode) {
        self.key.set_chain_code(chain_code)
    }
    fn hint(&self) -> Hint {
        self.key.hint()
    }
    fn set_hint(&mut self, hint: Hint) {
        self.key.set_hint(hint)
    }
    fn derive_child(&self, idx: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            key: self.key.derive_child(idx)?,
            derivation: self.derivation.extended(idx),
        })
    }
}


impl<'a, S, V, Sig, Rec> SigningKey for DerivedKey<S>
where
    Sig: SigSerialize,
    Rec: RecoverableSigSerialize<Signature = Sig>,
    V: VerifyingKey<SigningKey = S, Signature = Sig, RecoverableSignature = Rec>,
    S: SigningKey<VerifyingKey = V, Signature = Sig, RecoverableSignature = Rec>,
{
    type VerifyingKey = DerivedKey<V>;
    type Signature = Sig;
    type RecoverableSignature = Rec;

    fn to_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        Ok(DerivedKey {
            key: self.key.to_verifying_key()?,
            derivation: self.derivation.clone(),
        })
    }

    fn sign_digest(&self, message: [u8; 32]) -> Result<Self::Signature, Bip32Error> {
        self.key.sign_digest(message)
    }

    fn sign_digest_recoverable(
        &self,
        message: [u8; 32],
    ) -> Result<Rec, Bip32Error> {
        self.key.sign_digest_recoverable(message)
    }
}


impl<S, V, Sig, Rec> VerifyingKey for DerivedKey<V>
where
    Sig: SigSerialize,
    Rec: RecoverableSigSerialize< Signature = Sig>,
    V: VerifyingKey<SigningKey = S, Signature = Sig, RecoverableSignature = Rec>,
    S: SigningKey<VerifyingKey = V, Signature = Sig, RecoverableSignature = Rec>,
{
    type SigningKey = DerivedKey<S>;
    type Signature = Sig;
    type RecoverableSignature = Rec;

    fn from_signing_key(key: &Self::SigningKey) -> Result<Self, Bip32Error> {
        Ok(key.to_verifying_key()?)
    }

    fn verify_digest(&self, digest: [u8; 32], sig: &Sig) -> Result<(), Bip32Error> {
        self.key.verify_digest(digest, sig)
    }
}

#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub use self::keys::{DerivedXPriv, DerivedXPub};

#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
/// Pre-defined shortcuts for derived XPrivs and XPubs using the compiled-in backend
pub mod keys {
    use super::DerivedKey;

    use crate::{
        XPriv, XPub,
    };

    /// An XPriv coupled with its (purported) derivation path
    pub type DerivedXPriv<'a> = DerivedKey<XPriv<'a>>;

    /// An XPub coupled with its (purported) derivation path
    pub type DerivedXPub<'a> = DerivedKey<XPub<'a>>;
}
