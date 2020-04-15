//! Contains macros for use in this crate


macro_rules! wrap_prefixed_byte_vector {
    (
        $(#[$outer:meta])*
        $wrapper_name:ident
    ) => {
        $(#[$outer])*
        #[derive(Clone, Debug, Eq, PartialEq, Default, Ord, PartialOrd)]
        pub struct $wrapper_name(ConcretePrefixVec<u8>);

        impl PrefixVec for $wrapper_name {
            type Item = u8;

            fn null() -> Self {
                Self(Default::default())
            }

            fn set_items(&mut self, v: Vec<Self::Item>) {
                self.0.set_items(v)
            }

            fn push(&mut self, i: Self::Item) {
                self.0.push(i)
            }

            fn len(&self) -> usize {
                self.0.len()
            }

            fn len_prefix(&self) -> u8 {
                self.0.len_prefix()
            }

            fn items(&self) -> &[Self::Item] {
                self.0.items()
            }
        }

        impl<T> From<T> for $wrapper_name
        where
            T: Into<ConcretePrefixVec<u8>>
        {
            fn from(v: T) -> Self {
                Self(v.into())
            }
        }

        impl Index<usize> for $wrapper_name {
            type Output = u8;

            fn index(&self, index: usize) -> &Self::Output {
                &self.0[index]
            }
        }

        impl IndexMut<usize> for $wrapper_name {
            fn index_mut(&mut self, index: usize) -> &mut Self::Output {
                &mut self.0[index]
            }
        }

        impl Extend<u8> for $wrapper_name {
            fn extend<I: IntoIterator<Item=u8>>(&mut self, iter: I) {
                self.0.extend(iter)
            }
        }

        impl IntoIterator for $wrapper_name {
            type Item = u8;
            type IntoIter = std::vec::IntoIter<u8>;

            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter()
            }
        }
    }
}

// TOOD: make this repeat properly
macro_rules! impl_script_conversion {
    ($t1:ty, $t2:ty) => {

        impl From<$t2> for $t1 {
            fn from(t: $t2) -> $t1 {
                <$t1>::from_script(t.0)
            }
        }
        impl From<$t1> for $t2 {
            fn from(t: $t1) -> $t2 {
                <$t2>::from_script(t.0)
            }
        }
    }
}

macro_rules! mark_hash256 {
    (
        $(#[$outer:meta])*
        $hash_name:ident
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
        pub struct $hash_name(pub Hash256Digest);
        impl Ser for $hash_name {
            type Error = SerError;

            fn to_json(&self) -> String {
                format!("\"0x{}\"", self.serialize_hex().unwrap())
            }

            fn serialized_length(&self) -> usize {
                32
            }

            fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
            where
            R: Read,
            Self: std::marker::Sized
            {
                let mut buf = <Hash256Digest>::default();
                reader.read_exact(&mut buf)?;
                Ok(Self(buf))
            }

            fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
            where
            W: Write
            {
                Ok(writer.write(&self.0)?)
            }
        }
        impl MarkedDigest for $hash_name {
            type Digest = Hash256Digest;
            fn new(hash: Hash256Digest) -> Self {
                Self(hash)
            }

            fn internal(&self) -> Hash256Digest {
                self.0
            }
        }
        impl From<Hash256Digest> for $hash_name {
            fn from(h: Hash256Digest) -> Self {
                Self::new(h)
            }
        }
        impl Into<Hash256Digest> for $hash_name {
            fn into(self) -> Hash256Digest {
                self.internal()
            }
        }
    }
}
