use std::convert::TryInto;

use bitcoin_spv::btcspv::{hash256};

use crate::{curve::model::*, path::{DerivationPath, KeyDerivation}, xkeys::XKeyInfo, Bip32Error};

/// We treat the xpub/ypub/zpub convention as a hint regarding address type. Users are free to
/// follow or ignore these hints.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Hint {
    /// Standard Bip32 hint
    Legacy,
    /// Bip32 + Bip49 hint for Witness-via-P2SH
    Compatibility,
    /// Bip32 + Bip84 hint for Native SegWit
    SegWit,
}

/// A 4-byte key fingerprint
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct KeyFingerprint(pub [u8; 4]);

impl From<[u8; 4]> for KeyFingerprint {
    fn from(v: [u8; 4]) -> Self {
        Self(v)
    }
}

impl KeyFingerprint {
    /// Determines if the slice represents the same key fingerprint
    pub fn eq_slice(self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl std::fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("KeyFingerprint {:x?}", self.0))
    }
}

/// A 32-byte chain code
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct ChainCode(pub [u8; 32]);

impl From<[u8; 32]> for ChainCode {
    fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}


/// Any type that has access to a Secp256k1 backend.
pub trait HasBackend<'a, T: Secp256k1Backend<'a>> {
    /// Return a reference to the associated backend
    fn backend(&self) -> Result<&'a T, Bip32Error>;
}

/// Any type that contains a private key.
pub trait HasPrivkey<'a, T: Secp256k1Backend<'a>> {
    /// Return the associated private key
    fn privkey(&self) -> &T::Privkey;

    /// Return the 32 byte scalar as an array
    fn privkey_bytes(&self) -> [u8; 32] {
        self.privkey().privkey_array()
    }
}

/// Any type that contains a public key
pub trait HasPubkey<'a, T: Secp256k1Backend<'a>> {

    /// Return the associated public key
    fn pubkey(&self) -> &T::Pubkey;

    /// Return the associated public key in its compressed representation
    fn pubkey_bytes(&self) -> [u8; 33] {
        self.pubkey().pubkey_array()
    }

    /// Calculate the key fingerprint of the associated public key. This is the first 4 bytes of
    /// the Bitcoin HASH_160 of the compressed representation of the public key.
    /// For signing keys, this causes a pubkey derivation, which may fail.
    fn fingerprint(&self) -> KeyFingerprint {
        self.pubkey().fingerprint()
    }
}

/// Any type that has a private key and a backend may derive a public key.
/// This type is auto-implemented on any type that impls `HasPrivkey` and `HasBackend`
pub trait DerivesPubkey<'a, T: 'a + Secp256k1Backend<'a>>: HasPrivkey<'a, T> + HasBackend<'a, T> {
    /// Derive the public key. Note that this operation may fail if no backend is found. This
    /// call performs a scalar multiplication, so should be cached if possible.
    fn derive_pubkey(&self) -> Result<T::Pubkey, Bip32Error> {
        Ok(self.backend()?.derive_pubkey(&self.privkey()))
    }

    /// Derive the public key's fingerprint. Note that this operation may fail if no backend is
    /// found. This call performs a scalar multiplication, so should be cachedif possible.
    fn derive_fingerprint(&self) -> Result<KeyFingerprint, Bip32Error> {
        Ok(self.derive_pubkey()?.fingerprint())
    }
}

impl<'a, T, K> DerivesPubkey<'a, T> for K
where
    T: 'a + Secp256k1Backend<'a>,
    K: HasPrivkey<'a, T> + HasBackend<'a, T>
{}

/// Any type that has a private key and a backend may derive a public key
pub trait SigningKey<'a, T: 'a + Secp256k1Backend<'a>>: HasPrivkey<'a, T> + HasBackend<'a, T> + std::marker::Sized {
    /// The corresponding verifying key
    type VerifyingKey: VerifyingKey<'a, T, SigningKey = Self>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error>;

    /// Sign a digest
    fn sign_digest(&self, digest: [u8; 32]) -> Result<T::Signature, Bip32Error> {
        Ok(self.backend()?.sign_digest(&self.privkey(), digest))
    }

    /// Sign a digest and produce a recovery ID
    fn sign_digest_recoverable(
        &self,
        digest: [u8; 32],
    ) -> Result<T::RecoverableSignature, Bip32Error> {
        Ok(self.backend()?.sign_digest_recoverable(&self.privkey(), digest))
    }

    /// Sign a message
    fn sign_with_hash(
        &self,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<T::Signature, Bip32Error> {
        self.sign_digest(hash(message))
    }

    /// Sign a message and produce a recovery ID
    fn sign_recoverable_with_hash(
        &self,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<T::RecoverableSignature, Bip32Error> {
        self.sign_digest_recoverable(hash(message))
    }

    /// Produce a signature on `sha2(sha2(message))`
    fn sign(&self, message: &[u8]) -> Result<T::Signature, Bip32Error> {
        self.sign_with_hash(message, &|m| hash256(&[m]))
    }

    /// Produce a recoverable signature on `sha2(sha2(message))`
    fn sign_recoverable(&self, message: &[u8]) -> Result<T::RecoverableSignature, Bip32Error> {
        self.sign_recoverable_with_hash(message, &|m| hash256(&[m]))
    }
}

/// Any type that has a pubkey and a backend can verify signatures.
pub trait VerifyingKey<'a, T: 'a + Secp256k1Backend<'a>>: HasPubkey<'a, T> + HasBackend<'a, T> + std::marker::Sized {
    /// The corresponding signing key type.
    type SigningKey: SigningKey<'a, T, VerifyingKey = Self>;

    /// Instantiate `Self` from the corresponding signing key
    fn from_signing_key(key: &Self::SigningKey) -> Result<Self, Bip32Error> {
        key.derive_verifying_key()
    }

    /// Verify a signature on a digest
    fn verify_digest(&self, digest: [u8; 32], sig: &T::Signature) -> Result<(), Bip32Error> {
        self.backend()?
            .verify_digest(&self.pubkey(), digest, sig)
            .map_err(Into::into)
    }
}

/// Information about the extended key
pub trait HasXKeyInfo {
    /// Return the `XKeyInfo` object associated with the key
    fn xkey_info(&self) -> &XKeyInfo;
}

/// Extended Key common features
pub trait XKey: std::marker::Sized + Clone {
    /// Get the key's depth
    fn depth(&self) -> u8;
    /// Get the key's parent
    fn parent(&self) -> KeyFingerprint;
    /// Get the key's index
    fn index(&self) -> u32;
    /// Get the key's chain_code
    fn chain_code(&self) -> ChainCode;
    /// Get the key's hint
    fn hint(&self) -> Hint;
}

impl<T: HasXKeyInfo + std::marker::Sized + Clone> XKey for T {
    fn depth(&self) -> u8 {
        self.xkey_info().depth()
    }
    fn parent(&self) -> KeyFingerprint {
        self.xkey_info().parent()
    }
    fn index(&self) -> u32 {
        self.xkey_info().index()
    }
    fn chain_code(&self) -> ChainCode {
        self.xkey_info().chain_code()
    }
    fn hint(&self) -> Hint {
        self.xkey_info().hint()
    }
}

/// A trait for extended keys which can derive private children
pub trait DerivePrivateChild<'a, T: Secp256k1Backend<'a>>: XKey + HasPrivkey<'a, T> {
    /// Derive a child privkey
    fn derive_private_child(&self, index: u32) -> Result<Self, Bip32Error>;

    /// Derive a series of child indices. Allows traversing several levels of the tree at once.
    /// Accepts an iterator producing u32, or a string.
    fn derive_private_path<P, E>(&self, p: P) -> Result<Self, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        let path: DerivationPath = p.try_into().map_err(Into::into)?;

        if path.is_empty() {
            return Ok(self.to_owned());
        }

        let mut current = self.to_owned();
        for index in path.iter() {
            current = current.derive_private_child(*index)?;
        }
        Ok(current)
    }
}

/// A trait for extended keys which can derive public children
pub trait DerivePublicChild<'a, T: Secp256k1Backend<'a>>: XKey + HasPubkey<'a, T> {
    /// Derive a child pubkey
    fn derive_public_child(&self, index: u32) -> Result<Self, Bip32Error>;

    /// Derive a series of child indices. Allows traversing several levels of the tree at once.
    /// Accepts an iterator producing u32, or a string.
    fn derive_public_path<E, P>(&self, p: P) -> Result<Self, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        let path: DerivationPath = p.try_into().map_err(Into::into)?;

        if path.is_empty() {
            return Ok(self.to_owned());
        }

        let mut current = self.to_owned();
        for index in path.iter() {
            current = current.derive_public_child(*index)?;
        }
        Ok(current)
    }
}

/// Shortcuts for deriving and signing.
///
/// This trait is implemented on all types that impl `DerivePublicChild` and `VerifyingKey`
pub trait XSigning<'a, T: 'a + Secp256k1Backend<'a>>: DerivePrivateChild<'a, T> + SigningKey<'a, T> {
    /// Derive a descendant, and have it sign a digest
    fn descendant_sign_digest<E, P>(
        &self,
        path: P,
        digest: [u8; 32],
    ) -> Result<T::Signature, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.derive_private_path(path)?.sign_digest(digest)
    }

    /// Derive a descendant, and have it sign a digest and produce a recovery ID
    fn descendant_sign_digest_recoverable<E, P>(
        &self,
        path: P,
        digest: [u8; 32],
    ) -> Result<T::RecoverableSignature, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.derive_private_path(path)?.sign_digest_recoverable(digest)
    }

    /// Derive a descendant, and have it sign a message
    fn descendant_sign_with_hash<E, P>(
        &self,
        path: P,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<T::Signature, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_sign_digest(path, hash(message))
    }

    /// Derive a descendant, and have it sign a message and produce a recovery ID
    fn descendant_sign_recoverable_with_hash<E, P>(
        &self,
        path: P,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<T::RecoverableSignature, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_sign_digest_recoverable(path, hash(message))
    }

    /// Derive a descendant, and have it produce a signature on `sha2(sha2(message))`
    fn descendant_sign<E, P>(&self, path: P, message: &[u8]) -> Result<T::Signature, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_sign_with_hash(path, message, &|m| hash256(&[m]))
    }

    /// Derive a descendant, and have it produce a recoverable signature on `sha2(sha2(message))`
    fn descendant_sign_recoverable<E, P>(
        &self,
        path: P,
        message: &[u8],
    ) -> Result<T::RecoverableSignature, Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_sign_recoverable_with_hash(path, message, &|m| hash256(&[m]))
    }
}

/// Shortcuts for deriving and signing.
///
/// This trait is implemented on all types that impl `DerivePublicChild` and `VerifyingKey`
pub trait XVerifying<'a, T: 'a + Secp256k1Backend<'a>>: DerivePublicChild<'a, T> + VerifyingKey<'a, T> {
    /// Verify a signature on a digest
    fn descendant_verify_digest<P, E>(
        &self,
        path: P,
        digest: [u8; 32],
        sig: &T::Signature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.derive_public_path(path)?.verify_digest(digest, sig)
    }

    /// Verify a recoverable signature on a digest.
    fn descendant_verify_digest_recoverable<P, E>(
        &self,
        path: P,
        digest: [u8; 32],
        sig: &T::RecoverableSignature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_verify_digest(path, digest, &sig.without_recovery())
    }

    /// Verify a signature on a message
    fn descendant_verify_with_hash<P, E>(
        &self,
        path: P,
        message: &[u8],
        hash: &HashFunc,
        sig: &T::Signature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_verify_digest(path, hash(message), sig)
    }

    /// Verify a recoverable signature on a message.
    fn descendant_verify_recoverable_with_hash<P, E>(
        &self,
        path: P,
        message: &[u8],
        hash: &HashFunc,
        sig: &T::RecoverableSignature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_verify_digest(path, hash(message), &sig.without_recovery())
    }

    /// Produce a signature on `sha2(sha2(message))`
    fn descendant_verify<P, E>(
        &self,
        path: P,
        message: &[u8],
        sig: &T::Signature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_verify_with_hash(path, message, &|m| hash256(&[m]), sig)
    }

    /// Produce a recoverable signature on `sha2(sha2(message))`
    fn descendant_verify_recoverable<P, E>(
        &self,
        path: P,
        message: &[u8],
        sig: &T::RecoverableSignature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        self.descendant_verify_recoverable_with_hash(path, message, &|m| hash256(&[m]), sig)
    }
}

impl<'a, T, K> XSigning<'a, T> for K
where
    T: 'a + Secp256k1Backend<'a>,
    K: DerivePrivateChild<'a, T> + SigningKey<'a, T>,
{}

impl<'a, T, K> XVerifying<'a, T> for K
where
    T: 'a + Secp256k1Backend<'a>,
    K: DerivePublicChild<'a, T> + VerifyingKey<'a, T>,
{}

/// Comparison operations on keys based on their derivations
pub trait DerivedKey {
    /// Return this key's derivation
    fn derivation(&self) -> &KeyDerivation;

    /// `true` if the keys share a root fingerprint, `false` otherwise. Note that on key
    /// fingerprints, which may collide accidentally, or be intentionally collided.
    fn same_root<K: DerivedKey>(&self, other: &K) -> bool {
        self.derivation().same_root(&other.derivation())
    }

    /// `true` if this key is an ancestor of other, `false` otherwise. Note that on key
   /// fingerprints, which may collide accidentally, or be intentionally collided.
   fn is_possible_ancestor_of<K: DerivedKey>(&self, other: &K) -> bool {
       self.derivation().is_possible_ancestor_of(&other.derivation())
   }

   /// Returns the path to the decendant, or `None` if `descendant` is definitely not a
   /// descendant.
   /// This is useful for determining the path to rech some descendant from some ancestor.
   fn path_to_descendant<K: DerivedKey>(&self, other: &K)-> Option<DerivationPath> {
       self.derivation().path_to_descendant(&other.derivation())
   }
}
