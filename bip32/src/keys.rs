use crate::{
    curve::{ScalarSerialize, Secp256k1Backend},
    model::{CanDerivePubkey, HasBackend, HasPrivkey, HasPubkey, SigningKey, VerifyingKey},
    Bip32Error,
};

/// A Private Key using the crate's compiled-in backend.
/// This defaults to libsecp for native, and parity's rust secp for wasm targets.
///
/// For interface documentation see the page for
/// [GenericPrivkey](struct.GenericPrivkey.html).
pub type Privkey = GenericPrivkey<'static, crate::Secp256k1<'static>>;

/// A Public Key using the crate's compiled-in backend.
/// This defaults to libsecp for native, and parity's rust secp for wasm targets.
///
/// For interface documentation see the page for
/// [GenericPubkey](struct.GenericPubkey.html).
pub type Pubkey = GenericPubkey<'static, crate::Secp256k1<'static>>;

/// A Private key with a reference to its associated backend
#[derive(Copy, Clone, PartialEq)]
pub struct GenericPrivkey<'a, T: Secp256k1Backend> {
    /// The private key.
    pub key: T::Privkey,
    /// A reference to the backend. Many operations will return errors if this is None.
    pub backend: Option<&'a T>,
}

impl<T: Secp256k1Backend> std::fmt::Debug for GenericPrivkey<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Privkey")
            .field("key identifier", &self.key.short_id())
            .field("backend", &self.backend)
            .finish()
    }
}

impl<'a, T: Secp256k1Backend> HasPrivkey<'a, T> for GenericPrivkey<'a, T> {
    fn privkey(&self) -> &T::Privkey {
        &self.key
    }
}

impl<'a, T: Secp256k1Backend> HasBackend<'a, T> for GenericPrivkey<'a, T> {
    fn set_backend(&mut self, backend: &'a T) {
        self.backend = Some(backend);
    }

    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.backend.ok_or(Bip32Error::NoBackend)
    }
}

impl<'a, T: Secp256k1Backend> SigningKey<'a, T> for GenericPrivkey<'a, T> {
    /// The corresponding verifying key
    type VerifyingKey = GenericPubkey<'a, T>;

    /// Derive the corresponding pubkey
    fn derive_verifying_key(&self) -> Result<Self::VerifyingKey, Bip32Error> {
        Ok(GenericPubkey {
            key: self.derive_pubkey()?,
            backend: self.backend,
        })
    }
}

/// A Public key with a reference to its associated backend
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct GenericPubkey<'a, T: Secp256k1Backend> {
    /// The public key.
    pub key: T::Pubkey,
    /// A reference to the backend. Many operations will return errors if this is None.
    pub backend: Option<&'a T>,
}

impl<'a, T: Secp256k1Backend> GenericPubkey<'a, T> {
    /// Recover a public key from a signed digest
    pub fn recover_from_signed_digest(
        backend: &'a T,
        digest: [u8; 32],
        sig: &T::RecoverableSignature,
    ) -> Result<Self, Bip32Error> {
        Ok(Self {
            key: backend.recover_pubkey(digest, sig).map_err(Into::into)?,
            backend: Some(backend),
        })
    }
}

impl<'a, T: Secp256k1Backend> HasPubkey<'a, T> for GenericPubkey<'a, T> {
    fn pubkey(&self) -> &T::Pubkey {
        &self.key
    }
}

impl<'a, T: Secp256k1Backend> HasBackend<'a, T> for GenericPubkey<'a, T> {
    fn set_backend(&mut self, backend: &'a T) {
        self.backend = Some(backend);
    }

    fn backend(&self) -> Result<&'a T, Bip32Error> {
        self.backend.ok_or(Bip32Error::NoBackend)
    }
}

impl<'a, T: Secp256k1Backend> VerifyingKey<'a, T> for GenericPubkey<'a, T> {
    type SigningKey = GenericPrivkey<'a, T>;
}
