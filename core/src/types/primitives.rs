use std::{
    fmt::Debug,
    io::{Error as IOError, Read, Write},
    ops::{Index, IndexMut},
};

use crate::ser::{self, Ser, SerError};

/// A vector of items prefixed by a Bitcoin-style VarInt. The VarInt is encoded only as the length
/// of the vector, and minimal VarInts are mandatory.
///
/// The `PrefixVec` is a common Bitcoin datastructure, used throughout transactions and blocks.
pub trait PrefixVec: Ser {
    /// The Item that the represented vector contains.
    type Item: Ser;

    /// Construct an empty PrefixVec instance.
    fn null() -> Self;

    /// Set the underlying items vector.
    fn set_items(&mut self, v: Vec<Self::Item>);

    /// Push an item to the item vector.
    fn push(&mut self, i: Self::Item);

    /// Return the length of the item vector.
    fn len(&self) -> usize;

    /// Insert an item at the specified index.
    fn insert(&mut self, index: usize, i: Self::Item);

    /// Return the encoded length of the VarInt prefix.
    fn len_prefix(&self) -> u8 {
        ser::prefix_byte_len(self.len() as u64)
    }

    /// Return a reference to the contents of the item vector.
    fn items(&self) -> &[Self::Item];

    /// Return true if the length of the item vector is 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Instantiate a new `PrefixVec` that contains v.
    fn new(v: Vec<Self::Item>) -> Self
    where
        Self: std::marker::Sized,
    {
        let mut s = Self::null();
        s.set_items(v);
        s
    }
}

impl<E, I, T> Ser for T
where
    E: From<SerError> + From<IOError> + std::error::Error,
    I: Ser<Error = E>,
    T: PrefixVec<Item = I>,
{
    type Error = SerError;

    fn to_json(&self) -> String {
        let items: Vec<String> = self.items().iter().map(Ser::to_json).collect();
        format!(
            "{{\"length\": {}, \"items\": [{}]}}",
            self.len(),
            items.join(", ")
        )
    }

    fn serialized_length(&self) -> usize {
        let mut length = self.items().iter().map(|v| v.serialized_length()).sum();
        length += self.len_prefix() as usize;
        length
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> Result<T, Self::Error>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let num_items = Self::read_compact_int(reader)?;
        let vec = Vec::<I>::deserialize(reader, num_items as usize)
            .map_err(|e| SerError::ComponentError(format!("{}", e)))?;
        Ok(T::new(vec))
    }

    fn serialize<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write,
    {
        let varint_written = Self::write_comapct_int(writer, self.len() as u64)?;
        let writes: Result<Vec<usize>, _> = self
            .items()
            .iter()
            .map(|v| {
                v.serialize(writer)
                    .map_err(|e| SerError::ComponentError(format!("{}", e)))
            })
            .collect();
        let vec_written: usize = writes?.iter().sum();
        Ok(varint_written + vec_written)
    }
}

/// `ConcretePrefixVec` implements PrefixVec. We provide generic impls for indexing, and mutable
/// indexing, Into<Vec<T>> to ConcretePrefixVec<T>.
///
/// - `type Vin = ConcretePrefixVec<TxIn>`
/// - `type Vout  = ConcretePrefixVec<TxIn>
/// - `Scripts` are a newtype wrapping ConcretePrefixVec<u8>, and a passthrough implementation of
///     PrefixVec.
/// - `WitnessStackItems` are a newtype wrapping ConcretePrefixVec<u8>
/// - `type Witness = ConcretePrefixVec<WitnessStackItem>`
#[derive(PartialEq, Eq, Clone, Debug, Ord, PartialOrd)]
pub struct ConcretePrefixVec<T>(Vec<T>);

impl<T, E> PrefixVec for ConcretePrefixVec<T>
where
    E: From<SerError> + From<IOError> + std::error::Error,
    T: Ser<Error = E>,
{
    type Item = T;

    fn null() -> Self {
        Self(vec![])
    }

    fn set_items(&mut self, v: Vec<T>) {
        self.0 = v
    }

    fn push(&mut self, i: Self::Item) {
        self.0.push(i)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn items(&self) -> &[T] {
        &self.0
    }

    fn insert(&mut self, index: usize, i: Self::Item) {
        self.0.insert(index, i)
    }
}

impl<T> Default for ConcretePrefixVec<T>
where
    T: Ser,
{
    fn default() -> Self {
        Self::null()
    }
}

impl<T> Index<usize> for ConcretePrefixVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        &self.0[index]
    }
}

impl<T> Index<std::ops::Range<usize>> for ConcretePrefixVec<T> {
    type Output = [T];

    fn index(&self, range: std::ops::Range<usize>) -> &[T] {
        &self.0[range]
    }
}

impl<T> IndexMut<usize> for ConcretePrefixVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T, U> From<U> for ConcretePrefixVec<T>
where
    T: Ser,
    U: Into<Vec<T>>,
{
    fn from(v: U) -> Self {
        ConcretePrefixVec::<T>::new(v.into())
    }
}

impl<T> Extend<T> for ConcretePrefixVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter)
    }
}

impl<T> IntoIterator for ConcretePrefixVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Ser> std::iter::FromIterator<T> for ConcretePrefixVec<T> {
    fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self {
        Vec::from_iter(iter).into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn basic_functionality() {
        let mut c = ConcretePrefixVec::<u8>::null();
        c.push(0);
        assert_eq!(c[0], 0);

        // IntoIterator and FromIterator
        c = c.into_iter().chain(std::iter::once(1)).collect();
        assert_eq!(c[0], 0);
        assert_eq!(c[1], 1);

        // extend
        c.extend(c.clone());

        // insert
        c.insert(2, 2);

        // range indexing
        assert_eq!(c[0..5], [0, 1, 2, 0, 1]);
    }
}
