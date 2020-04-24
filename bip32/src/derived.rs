use crate::{
    model::*,
    path::{DerivationPath, KeyDerivation},
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

impl<T: XKey> XKey for DerivedKey<T> {
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
    fn pubkey_bytes(&self) -> Result<[u8; 33], Bip32Error> {
        self.key.pubkey_bytes()
    }
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        Ok(Self {
            key: self.key.derive_child(index)?,
            derivation: self.derivation.extended(index),
        })
    }
}

impl<T> DerivedKey<T> {
    /// `true` if the keys share a root fingerprint, `false` otherwise. Note that on key
    /// fingerprints, which may collide accidentally, or be intentionally collided.
    pub fn same_root<K>(&self, other: &DerivedKey<K>) -> bool {
        self.derivation.same_root(&other.derivation)
    }

    /// `true` if this key is an ancestor of other, `false` otherwise. Note that on key
    /// fingerprints, which may collide accidentally, or be intentionally collided.
    pub fn is_possible_ancestor_of<K>(&self, other: &DerivedKey<K>) -> bool {
        self.derivation.is_possible_ancestor_of(&other.derivation)
    }

    /// Returns the path to the decendant, or `None` if `descendant` is definitely not a
    /// descendant.
    /// This is useful for determining the path to rech some descendant from some ancestor.
    pub fn path_to_descendant<K>(&self, descendant: &DerivedKey<K>) -> Option<DerivationPath> {
        self.derivation.path_to_descendant(&descendant.derivation)
    }
}

impl<K> PointSerialize for DerivedKey<K>
where
    K: PointSerialize
{
    fn to_array(&self) -> [u8; 33] {
        self.key.to_array()
    }

    fn to_array_uncompressed(&self) -> [u8; 65] {
        self.key.to_array_uncompressed()
    }

    fn from_array(_buf: [u8; 33]) -> Result<Self, Bip32Error> {
        Err(Bip32Error::InvalidBip32Path)
    }

    fn from_array_uncompressed(_buf: [u8; 65]) -> Result<Self, Bip32Error> {
        Err(Bip32Error::InvalidBip32Path)
    }
}

impl<K> ScalarSerialize for DerivedKey<K>
where
    K: ScalarSerialize
{
    fn to_array(&self) -> [u8; 32] {
        self.key.to_array()
    }

    fn from_array(_buf: [u8; 32]) -> Result<Self, Bip32Error> {
        Err(Bip32Error::InvalidBip32Path)
    }
}

impl<'a, S, V, Sig, Rec> DerivedKey<S>
where
    Sig: SigSerialize,
    Rec: RecoverableSigSerialize<Signature = Sig>,
    V: VerifyingKey<SigningKey = S, Signature = Sig, RecoverableSignature = Rec>,
    S: XKey + SigningKey<VerifyingKey = V, Signature = Sig, RecoverableSignature = Rec>,
{
    /// Determine whether `self` is an ancestor of `descendant` by attempting to derive the path
    /// between them. Returns true if both the fingerprint and the parent fingerprint match.
    ///
    /// Note that a malicious party can fool this by trying 2**64 derivations (2**32 derivations)
    /// in a birthday attack setting).
    pub fn private_ancestor_of<K: PointSerialize>(&self, descendant: &DerivedKey<K>) -> Result<bool, Bip32Error> {
        if !self.is_possible_ancestor_of(descendant) {
            return Ok(false);
        }

        let path = self
            .path_to_descendant(descendant)
            .expect("pre-flighted by is_possible_ancestor_of");

        let derived = self.derive_path(&path)?.to_verifying_key()?;
        Ok(derived.to_array()[..] == descendant.to_array()[..])
    }
}

impl<S, V, Sig, Rec> DerivedKey<V>
where
    Sig: SigSerialize,
    Rec: RecoverableSigSerialize<Signature = Sig>,
    S: SigningKey<VerifyingKey = V, Signature = Sig, RecoverableSignature = Rec>,
    V: XKey + VerifyingKey<SigningKey = S, Signature = Sig, RecoverableSignature = Rec>,
{
    /// Determine whether `self` is an ancestor of `descendant` by attempting to derive the path
    /// between them. Returns true if both the fingerprint and the parent fingerprint match.
    ///
    /// Note that a malicious party can fool this by trying 2**64 derivations (2**32 derivations)
    /// in a birthday attack setting).
    pub fn public_ancestor_of<K: PointSerialize>(&self, descendant: &DerivedKey<K>) -> Result<bool, Bip32Error> {
        if !self.is_possible_ancestor_of(descendant) {
            return Ok(false);
        }

        let path = self
            .path_to_descendant(descendant)
            .expect("pre-flighted by is_possible_ancestor_of");

        let derived = self.derive_path(&path)?;
        Ok(derived.to_array()[..] == descendant.to_array()[..])
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

    fn sign_digest_recoverable(&self, message: [u8; 32]) -> Result<Rec, Bip32Error> {
        self.key.sign_digest_recoverable(message)
    }
}

impl<S, V, Sig, Rec> VerifyingKey for DerivedKey<V>
where
    Sig: SigSerialize,
    Rec: RecoverableSigSerialize<Signature = Sig>,
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
pub use self::keys::{DerivedPrivkey, DerivedPubkey, DerivedXPriv, DerivedXPub};

#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
/// Pre-defined shortcuts for derived XPrivs and XPubs using the compiled-in backend
pub mod keys {
    use super::*;

    use crate::{Privkey, Pubkey, Secp256k1, XKey, XPriv, XPub};

    /// An XPriv coupled with its (purported) derivation path
    pub type DerivedXPriv<'a> = DerivedKey<XPriv<'a>>;

    /// An XPub coupled with its (purported) derivation path
    pub type DerivedXPub<'a> = DerivedKey<XPub<'a>>;

    impl<'a> DerivedXPriv<'a> {
        /// Generate a master node from some seed data. Uses the BIP32-standard hmac key.
        ///
        ///
        /// # Important:
        ///
        /// Use a seed of AT LEAST 128 bits.
        pub fn root_from_seed(
            data: &[u8],
            hint: Option<Hint>,
            backend: &'a Secp256k1,
        ) -> Result<Self, Bip32Error> {
            let key = XPriv::root_from_seed(data, hint, backend)?;
            let derivation = KeyDerivation {
                root: key.fingerprint()?,
                path: vec![].into(),
            };
            Ok(Self { key, derivation })
        }

        /// Return a `Pubkey` corresponding to the private key
        pub fn pubkey(&self) -> Result<Pubkey, Bip32Error> {
            self.key.pubkey()
        }

        /// Return the secret key as an array
        pub fn secret_key(&self) -> [u8; 32] {
            self.key.secret_key()
        }
    }

    /// A Privkey coupled with its (purported) derivation path
    pub type DerivedPrivkey = DerivedKey<Privkey>;

    /// A Pubkey coupled with its (purported) derivation path
    pub type DerivedPubkey = DerivedKey<Pubkey>;
}
