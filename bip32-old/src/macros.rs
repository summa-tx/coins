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
        #[derive(Debug, Clone)]
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

macro_rules! inherit_backend {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend> crate::model::HasBackend<'a, T>
            for $struct_name<'a, T>
        {
            fn set_backend(&mut self, backend: &'a T) {
                self.$attr.set_backend(backend)
            }

            fn backend(&self) -> Result<&'a T, Bip32Error> {
                self.$attr.backend()
            }
        }
    };
}

macro_rules! inherit_has_privkey {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend> crate::model::HasPrivkey<'a, T>
            for $struct_name<'a, T>
        {
            fn privkey(&self) -> &T::Privkey {
                self.$attr.privkey()
            }
        }
    };
}

macro_rules! inherit_has_pubkey {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend> crate::model::HasPubkey<'a, T>
            for $struct_name<'a, T>
        {
            fn pubkey(&self) -> &T::Pubkey {
                self.$attr.pubkey()
            }
        }
    };
}

macro_rules! inherit_has_xkeyinfo {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend> crate::model::HasXKeyInfo
            for $struct_name<'a, T>
        {
            fn xkey_info(&self) -> &crate::primitives::XKeyInfo {
                self.$attr.xkey_info()
            }
        }
    };
}

macro_rules! make_derived_key {
    (
        $(#[$outer:meta])*
        $underlying:ident, $struct_name:ident.$attr:ident
    ) => {
        $(#[$outer])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $struct_name<'a, T: Secp256k1Backend> {
            /// The underlying key
            pub $attr: $underlying<'a, T>,
            /// Its derivation from some master key
            pub derivation: crate::path::KeyDerivation,
        }

        impl<'a, T: Secp256k1Backend> crate::model::DerivedKey for $struct_name<'a, T> {
            type Key = $underlying<'a, T>;

            fn new(k: Self::Key, derivation: KeyDerivation) -> Self {
                Self {
                    $attr: k,
                    derivation,
                }
            }

            fn derivation(&self) -> &KeyDerivation {
                &self.derivation
            }
        }
    }
}
