macro_rules! inherit_backend {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend<'a>> crate::model::HasBackend<'a, T> for $struct_name<'a, T> {
            fn set_backend(&mut self, backend: &'a T) {
                self.$attr.set_backend(backend)
            }

            fn backend(&self) -> Result<&'a T, Bip32Error> {
                self.$attr.backend()
            }
        }
    }
}

macro_rules! inherit_has_privkey {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend<'a>> crate::model::HasPrivkey<'a, T> for $struct_name<'a, T> {
            fn privkey(&self) -> &T::Privkey {
                self.$attr.privkey()
            }
        }
    }
}


macro_rules! inherit_has_pubkey {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend<'a>> crate::model::HasPubkey<'a, T> for $struct_name<'a, T> {
            fn pubkey(&self) -> &T::Pubkey {
                self.$attr.pubkey()
            }
        }
    }
}

macro_rules! inherit_has_xkeyinfo {
    ($struct_name:ident.$attr:ident) => {
        impl<'a, T: crate::curve::model::Secp256k1Backend<'a>> crate::model::HasXKeyInfo for $struct_name<'a, T> {
            fn xkey_info(&self) -> &XKeyInfo {
                self.$attr.xkey_info()
            }
        }
    }
}
