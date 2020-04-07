use std::ops::{Index, IndexMut};
use std::io::{Read, Write};

use crate::ser::{self, Ser, SerResult};

/// A vector of items prefixed by a Bitcoin-style VarInt. The VarInt is encoded only as the length
/// of the vector, and the serialized length of the VarInt.
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
        Self: std::marker::Sized
     {
        let mut s = Self::null();
        s.set_items(v);
        s
    }
}

impl<T, I> Ser for T
where
    I: Ser,
    T: PrefixVec<Item = I>,
{
    fn to_json(&self) -> String {
        let items: Vec<String> = self.items().iter().map(Ser::to_json).collect();
        format!("{{\"prefix_bytes\": {}, \"items\": [{}]}}", self.len_prefix(), items.join(", "))
    }

    fn serialized_length(&self) -> usize {
        let mut length = self.items().iter().map(|v| v.serialized_length()).sum();
        length += self.len_prefix() as usize;
        length
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<T>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let num_items = Self::read_compact_int(reader)?;
        let vec = Vec::<I>::deserialize(reader, num_items as usize)?;
        Ok(T::new(vec))
    }

    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write
    {
        let varint_written = Self::write_comapct_int(writer, self.len() as u64)?;
        let writes: SerResult<Vec<usize>> = self.items()
            .iter()
            .map(|v| v.serialize(writer))
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
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConcretePrefixVec<T>(Vec<T>);

impl<T: Ser> PrefixVec for ConcretePrefixVec<T>
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
}

impl<T> Default for ConcretePrefixVec<T>
where
    T: Ser
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

impl<T> IndexMut<usize> for ConcretePrefixVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T, U> From<U> for ConcretePrefixVec<T>
where
    T: Ser,
    U: Into<Vec<T>>
{
    fn from(v: U) -> Self {
        ConcretePrefixVec::<T>::new(v.into())
    }
}

impl<T> Extend<T> for ConcretePrefixVec<T> {
    fn extend<I: IntoIterator<Item=T>>(&mut self, iter: I) {
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
