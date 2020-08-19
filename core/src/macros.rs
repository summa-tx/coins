//! Useful macros for implementing new chains

#[macro_export]
/// Implement `serde::Serialize` and `serde::Deserialize` by passing through to the hex
macro_rules! impl_hex_serde {
    ($item:ty) => {
        impl serde::Serialize for $item {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let s = $crate::ser::ByteFormat::serialize_hex(self);
                serializer.serialize_str(&s)
            }
        }

        impl<'de> serde::Deserialize<'de> for $item {
            fn deserialize<D>(deserializer: D) -> Result<$item, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s: &str = serde::Deserialize::deserialize(deserializer)?;
                <$item as $crate::ser::ByteFormat>::deserialize_hex(s)
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            }
        }
    };
}

#[macro_export]
/// Wrap a prefixed vector of bytes (`u8`) in a newtype, and implement convenience functions for
/// it.
macro_rules! wrap_prefixed_byte_vector {
    (
        $(#[$outer:meta])*
        $wrapper_name:ident
    ) => {
        $(#[$outer])*
        #[derive(Clone, Debug, Eq, PartialEq, Default, Hash, PartialOrd, Ord)]
        pub struct $wrapper_name(Vec<u8>);

        impl $crate::ser::ByteFormat for $wrapper_name {
            type Error = $crate::ser::SerError;

            fn serialized_length(&self) -> usize {
                let mut length = self.len();
                length += self.len_prefix() as usize;
                length
            }

            fn read_from<R>(reader: &mut R, _limit: usize) -> Result<Self, Self::Error>
            where
                R: std::io::Read
            {
                Ok(Self::read_prefix_vec(reader)?.into())
            }

            fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
            where
                W: std::io::Write
            {
                Ok(Self::write_prefix_vec(writer, &self.0)?)
            }
        }

        impl_hex_serde!($wrapper_name);

        impl std::convert::AsRef<[u8]> for $wrapper_name {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl $wrapper_name {
            /// Instantate a new wrapped vector
            pub fn new(v: Vec<u8>) -> Self {
                Self(v)
            }

            /// Construct an empty wrapped vector instance.
            pub fn null() -> Self {
                Self(vec![])
            }

            /// Return a reference to the underlying bytes
            pub fn items(&self) -> &[u8] {
                &self.0
            }

            /// Set the underlying items vector.
            pub fn set_items(&mut self, v: Vec<u8>) {
                self.0 = v
            }

            /// Push an item to the item vector.
            pub fn push(&mut self, i: u8) {
                self.0.push(i)
            }

            /// Return the length of the item vector.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Return true if the length of the item vector is 0.
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }

            /// Determine the byte-length of the vector length prefix
            pub fn len_prefix(&self) -> u8 {
                $crate::ser::prefix_byte_len(self.len() as u64)
            }

            /// Insert an item at the specified index.
            pub fn insert(&mut self, index: usize, i: u8) {
                self.0.insert(index, i)
            }
        }

        impl From<&[u8]> for $wrapper_name {
            fn from(v: &[u8]) -> Self {
                Self(v.to_vec())
            }
        }

        impl From<Vec<u8>> for $wrapper_name {
            fn from(v: Vec<u8>) -> Self {
                Self(v)
            }
        }

        impl std::ops::Index<usize> for $wrapper_name {
            type Output = u8;

            fn index(&self, index: usize) -> &Self::Output {
                &self.0[index]
            }
        }

        impl std::ops::Index<std::ops::Range<usize>> for $wrapper_name {
            type Output = [u8];

            fn index(&self, range: std::ops::Range<usize>) -> &[u8] {
                &self.0[range]
            }
        }

        impl std::ops::IndexMut<usize> for $wrapper_name {
            fn index_mut(&mut self, index: usize) -> &mut Self::Output {
                &mut self.0[index]
            }
        }

        impl std::iter::Extend<u8> for $wrapper_name {
            fn extend<I: std::iter::IntoIterator<Item=u8>>(&mut self, iter: I) {
                self.0.extend(iter)
            }
        }

        impl std::iter::IntoIterator for $wrapper_name {
            type Item = u8;
            type IntoIter = std::vec::IntoIter<u8>;

            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter()
            }
        }
    }
}

#[macro_export]
/// Implement conversion between script types by passing via `as_ref().into()`
macro_rules! impl_script_conversion {
    ($t1:ty, $t2:ty) => {
        impl From<&$t2> for $t1 {
            fn from(t: &$t2) -> $t1 {
                t.as_ref().into()
            }
        }
        impl From<&$t1> for $t2 {
            fn from(t: &$t1) -> $t2 {
                t.as_ref().into()
            }
        }
    };
}

#[macro_export]
/// Make a new marked digest based on .
macro_rules! mark_32_byte_hash {
    (
        $(#[$outer:meta])*
        $hash_name:ident, $base_type:ty
    ) => {
        $(#[$outer])*
        #[derive(Hash, serde::Serialize, serde::Deserialize, Copy, Clone, Default, Debug, Eq, PartialEq)]
        pub struct $hash_name(pub $base_type);

        impl $hash_name {
            /// Deserialize to BE hex
            pub fn from_be_hex(be: &str) -> $crate::ser::SerResult<Self> {
                Ok(<Self as $crate::ser::ByteFormat>::deserialize_hex(be)?.reversed())
            }

            /// Convert to BE hex
            pub fn to_be_hex(&self) -> String {
                $crate::ser::ByteFormat::serialize_hex(&self.reversed())
            }
        }

        impl From<[u8; 32]> for $hash_name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes.into())
            }
        }

        impl AsRef<[u8; 32]> for $hash_name {
            fn as_ref(&self) -> &[u8; 32] {
                self.0.as_ref()
            }
        }

        impl $crate::ser::ByteFormat for $hash_name {
            type Error = $crate::ser::SerError;

            fn serialized_length(&self) -> usize {
                32
            }

            fn read_from<R>(reader: &mut R, _limit: usize) -> $crate::ser::SerResult<Self>
            where
                R: std::io::Read,
                Self: std::marker::Sized
            {
                let mut buf = <$base_type>::default();
                reader.read_exact(buf.as_mut())?;
                Ok(Self(buf))
            }

            fn write_to<W>(&self, writer: &mut W) -> $crate::ser::SerResult<usize>
            where
                W: std::io::Write
            {
                Ok(writer.write(self.0.as_ref())?)
            }
        }

        impl $crate::hashes::MarkedDigest for $hash_name {
            type Digest = $base_type;
            fn new(hash: $base_type) -> Self {
                Self(hash)
            }

            fn internal(&self) -> $base_type {
                self.0
            }

            fn bytes(&self) -> Vec<u8> {
                self.0.as_ref().to_vec()
            }
        }

        impl From<$base_type> for $hash_name {
            fn from(h: $base_type) -> Self {
                Self::new(h)
            }
        }
        impl Into<$base_type> for $hash_name {
            fn into(self) -> $base_type {
                self.internal()
            }
        }
    }
}
