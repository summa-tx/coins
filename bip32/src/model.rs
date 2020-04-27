use std::convert::TryInto;

use bitcoin_spv::btcspv::hash256;

use crate::{
    Bip32Error,
    curve::model::*,
    path::DerivationPath,
};

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

/// Extended Key common features
pub trait XKey: std::marker::Sized + Clone {
    /// Calculate and return the key fingerprint
    fn fingerprint(&self) -> Result<KeyFingerprint, Bip32Error>;
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

    /// Return the 33-byte compressed pubkey representation
    fn pubkey_bytes(&self) -> Result<[u8; 33], Bip32Error>;

    /// Derive a child key. Private keys derive private children, public keys derive public
    /// children.
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error>;

    /// Derive a series of child indices. Allows traversing several levels of the tree at once.
    /// Accepts an iterator producing u32, or a string.
    fn derive_path<E, T>(&self, p: &T) -> Result<Self, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        let path: DerivationPath = p.clone().try_into().map_err(Into::into)?;

        if path.is_empty() {
            return Ok(self.to_owned());
        }

        let mut current = self.to_owned();
        for index in path.iter() {
            current = current.derive_child(*index)?;
        }
        Ok(current)
    }
}

/// Shortcuts for deriving and signing. Generically implemented on any type that impls SigningKey
/// and XKey
pub trait XSigning: XKey + SigningKey {
    /// Derive a descendant, and have it sign a digest
    fn descendant_sign_digest<E, T>(
        &self,
        path: &T,
        digest: [u8; 32],
    ) -> Result<Self::Signature, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.derive_path(path)?.sign_digest(digest)
    }

    /// Derive a descendant, and have it sign a digest and produce a recovery ID
    fn descendant_sign_digest_recoverable<E, T>(
        &self,
        path: &T,
        digest: [u8; 32],
    ) -> Result<Self::RecoverableSignature, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.derive_path(path)?.sign_digest_recoverable(digest)
    }

    /// Derive a descendant, and have it sign a message
    fn descendant_sign_with_hash<E, T>(
        &self,
        path: &T,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<Self::Signature, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_sign_digest(path, hash(message))
    }

    /// Derive a descendant, and have it sign a message and produce a recovery ID
    fn descendant_sign_recoverable_with_hash<E, T>(
        &self,
        path: &T,
        message: &[u8],
        hash: &HashFunc,
    ) -> Result<Self::RecoverableSignature, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_sign_digest_recoverable(path, hash(message))
    }

    /// Derive a descendant, and have it produce a signature on `sha2(sha2(message))`
    fn descendant_sign<E, T>(&self, path: &T, message: &[u8]) -> Result<Self::Signature, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_sign_with_hash(path, message, &|m| hash256(&[m]))
    }

    /// Derive a descendant, and have it produce a recoverable signature on `sha2(sha2(message))`
    fn descendant_sign_recoverable<E, T>(
        &self,
        path: &T,
        message: &[u8],
    ) -> Result<Self::RecoverableSignature, Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_sign_recoverable_with_hash(path, message, &|m| hash256(&[m]))
    }
}

/// Shortcuts for deriving and signing. Generically implemented on any type that impls
/// VerifyingKey and XKey
pub trait XVerifying: XKey + VerifyingKey {
    /// Verify a signature on a digest
    fn descendant_verify_digest<T, E>(
        &self,
        path: &T,
        digest: [u8; 32],
        sig: &Self::Signature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.derive_path(path)?.verify_digest(digest, sig)
    }

    /// Verify a recoverable signature on a digest.
    fn descendant_verify_digest_recoverable<T, E>(
        &self,
        path: &T,
        digest: [u8; 32],
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_verify_digest(path, digest, &sig.without_recovery())
    }

    /// Verify a signature on a message
    fn descendant_verify_with_hash<T, E>(
        &self,
        path: &T,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::Signature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_verify_digest(path, hash(message), sig)
    }

    /// Verify a recoverable signature on a message.
    fn descendant_verify_recoverable_with_hash<T, E>(
        &self,
        path: &T,
        message: &[u8],
        hash: &HashFunc,
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_verify_digest(path, hash(message), &sig.without_recovery())
    }

    /// Produce a signature on `sha2(sha2(message))`
    fn descendant_verify<T, E>(
        &self,
        path: &T,
        message: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_verify_with_hash(path, message, &|m| hash256(&[m]), sig)
    }

    /// Produce a recoverable signature on `sha2(sha2(message))`
    fn descendant_verify_recoverable<T, E>(
        &self,
        path: &T,
        message: &[u8],
        sig: &Self::RecoverableSignature,
    ) -> Result<(), Bip32Error>
    where
        E: Into<Bip32Error>,
        T: TryInto<DerivationPath, Error = E> + Clone,
    {
        self.descendant_verify_recoverable_with_hash(path, message, &|m| hash256(&[m]), sig)
    }
}

impl<T> XSigning for T where T: XKey + SigningKey {}

impl<T> XVerifying for T where T: XKey + VerifyingKey {}
