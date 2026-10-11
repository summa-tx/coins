macro_rules! inherit_signer {
    ($struct_name:ident.$attr:ident) => {
        impl<D> k256::ecdsa::signature::DigestSigner<D, k256::ecdsa::Signature> for $struct_name
        where
            D: digest::FixedOutput<OutputSize = k256::elliptic_curve::consts::U32>
                + Clone
                + Default
                + digest::Reset
                + digest::Update
                + digest::HashMarker,
        {
            fn try_sign_digest<F: Fn(&mut D) -> Result<(), k256::ecdsa::Error>>(
                &self,
                f: F,
            ) -> Result<k256::ecdsa::Signature, k256::ecdsa::Error> {
                self.$attr.try_sign_digest(f)
            }
        }

        impl<D>
            k256::ecdsa::signature::DigestSigner<
                D,
                (k256::ecdsa::Signature, k256::ecdsa::RecoveryId),
            > for $struct_name
        where
            D: digest::FixedOutput<OutputSize = k256::elliptic_curve::consts::U32>
                + Clone
                + Default
                + digest::Reset
                + digest::Update
                + digest::HashMarker,
        {
            fn try_sign_digest<F: Fn(&mut D) -> Result<(), k256::ecdsa::Error>>(
                &self,
                f: F,
            ) -> Result<(k256::ecdsa::Signature, k256::ecdsa::RecoveryId), k256::ecdsa::Error> {
                self.$attr.try_sign_digest(f)
            }
        }

        impl $struct_name {
            /// Sign a pre-filled hasher. Convenience wrapper for
            /// [`DigestSigner`](k256::ecdsa::signature::DigestSigner), which takes a closure.
            pub fn sign_hasher<D>(
                &self,
                digest: D,
            ) -> Result<k256::ecdsa::Signature, k256::ecdsa::Error>
            where
                D: digest::FixedOutput<OutputSize = k256::elliptic_curve::consts::U32>,
            {
                use k256::ecdsa::signature::hazmat::PrehashSigner as _;
                let key: &k256::ecdsa::SigningKey = self.as_ref();
                key.sign_prehash(&digest.finalize_fixed())
            }

            /// Sign the given message digest, returning a signature and recovery ID.
            /// See [ECDSA docs here](https://docs.rs/ecdsa/latest/ecdsa/struct.SigningKey.html#method.sign_digest_recoverable)
            pub fn sign_digest_recoverable<D>(
                &self,
                digest: D,
            ) -> Result<(k256::ecdsa::Signature, k256::ecdsa::RecoveryId), k256::ecdsa::Error>
            where
                D: digest::FixedOutput<OutputSize = k256::elliptic_curve::consts::U32>
                    + Clone
                    + Default
                    + digest::Reset
                    + digest::Update
                    + digest::HashMarker,
            {
                let key: &k256::ecdsa::SigningKey = self.as_ref();
                Ok(key.sign_digest_recoverable(digest))
            }
        }
    };
}

macro_rules! inherit_verifier {
    ($struct_name:ident.$attr:ident) => {
        impl $struct_name {
            /// Get the compressed sec1 representation of the public key.
            pub fn to_sec1_bytes(&self) -> [u8; 33] {
                let mut data = [0u8; 33];
                let generic_array = self.$attr.to_sec1_bytes();
                data.copy_from_slice(&generic_array);
                data
            }

            /// Verify a signature against a pre-filled hasher. Convenience wrapper for
            /// [`DigestVerifier`](k256::ecdsa::signature::DigestVerifier), which takes a closure.
            pub fn verify_hasher<D>(
                &self,
                digest: D,
                signature: &k256::ecdsa::Signature,
            ) -> Result<(), k256::ecdsa::Error>
            where
                D: digest::FixedOutput<OutputSize = k256::elliptic_curve::consts::U32>,
            {
                use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
                let key: &k256::ecdsa::VerifyingKey = self.as_ref();
                key.verify_prehash(&digest.finalize_fixed(), signature)
            }
        }

        impl<D> k256::ecdsa::signature::DigestVerifier<D, k256::ecdsa::Signature> for $struct_name
        where
            D: digest::Digest + digest::FixedOutput<OutputSize = k256::elliptic_curve::consts::U32>,
        {
            fn verify_digest<F: Fn(&mut D) -> Result<(), k256::ecdsa::Error>>(
                &self,
                f: F,
                signature: &k256::ecdsa::Signature,
            ) -> Result<(), k256::ecdsa::Error> {
                self.$attr.verify_digest(f, signature)
            }
        }
    };
}

macro_rules! params {
    (
        $(#[$outer:meta])*
        $name:ident{
            bip32: $bip32:expr,
            bip49: $bip49:expr,
            bip84: $bip84:expr,
            bip32_pub: $bip32pub:expr,
            bip49_pub: $bip49pub:expr,
            bip84_pub: $bip84pub:expr
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy)]
        pub struct $name;

        impl crate::enc::NetworkParams for $name {
            const PRIV_VERSION: u32 = $bip32;
            const BIP49_PRIV_VERSION: u32 = $bip49;
            const BIP84_PRIV_VERSION: u32 = $bip84;
            const PUB_VERSION: u32 = $bip32pub;
            const BIP49_PUB_VERSION: u32 = $bip49pub;
            const BIP84_PUB_VERSION: u32 = $bip84pub;
        }
    }
}
