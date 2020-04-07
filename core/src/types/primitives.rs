use std::ops::{Index, IndexMut};
use std::io::{Read, Write};

use crate::ser::{Ser, SerError, SerResult};

/// Calculates the minimum prefix length for a VarInt encoding `number`
pub fn prefix_byte_len(number: u64) -> u8 {
    match number {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9
    }
}

/// Matches the length of the VarInt to the 1-byte flag
pub fn first_byte_from_len(number: u8) -> Option<u8> {
    match number {
         3 =>  Some(0xfd),
         5 =>  Some(0xfe),
         9 =>  Some(0xff),
         _ => None
    }
}

/// Matches the VarInt prefix flag to the serialized length
pub fn prefix_len_from_first_byte(number: u8) -> u8 {
    match number {
        0..=0xfc => 1,
        0xfd => 3,
        0xfe => 5,
        0xff => 9
    }
}

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
        prefix_byte_len(self.len() as u64)
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
        let mut prefix = [0u8; 1];
        reader.read_exact(&mut prefix)?;  // read at most one byte
        let prefix_len = prefix_len_from_first_byte(prefix[0]);

        // Get the byte(s) representing the vector length, and parse as u64
        let expected_vector_length = if prefix_len > 1 {
            let mut buf = [0u8; 8];
            let mut body = reader.take(prefix_len as u64 - 1); // minus 1 to account for prefix
            let _ = body.read(&mut buf)?;
            u64::from_le_bytes(buf)
        } else {
            prefix[0] as u64
        };

        let expected_prefix_length = prefix_byte_len(expected_vector_length);
        if expected_prefix_length < prefix_len {
            Err(SerError::NonMinimalVarInt)
        } else {
            let vec = Vec::<I>::deserialize(reader, expected_vector_length as usize)?;
            Ok(T::new(vec))
        }
    }

    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write
    {
        // Write the VarInt prefix first
        let prefix_len = self.len_prefix();
        let written: usize = match first_byte_from_len(prefix_len) {
            None => writer.write(&[self.items().len() as u8])?,
            Some(prefix) => {
                let body = (self.items().len() as u64).to_le_bytes();
                let mut written = writer.write(&[prefix])?;
                written += writer.write(&body[.. prefix_len as usize - 1])?;
                written
            }
        };
        let writes: SerResult<Vec<usize>> = self.items()
            .iter()
            .map(|v| v.serialize(writer))
            .collect();
        let vec_written: usize = writes?.iter().sum();
        Ok(written + vec_written)
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

impl<T: Ser> Default for ConcretePrefixVec<T> {
    fn default() -> Self {
        PrefixVec::null()
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

impl<T:Ser, U> From<U> for ConcretePrefixVec<T>
where
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

impl Ser for u8 {
    fn to_json(&self) -> String {
        format!("{}", self)
    }

    fn serialized_length(&self) -> usize {
        1
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(u8::from_le_bytes(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write
    {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_matches_byte_len_and_prefix() {
        let cases = [
            (1, 1, None),
            (0xff, 3, Some(0xfd)),
            (0xffff_ffff, 5, Some(0xfe)),
            (0xffff_ffff_ffff_ffff, 9, Some(0xff))];
        for case in cases.iter() {
            assert_eq!(prefix_byte_len(case.0), case.1);
            assert_eq!(first_byte_from_len(case.1), case.2);
        }
    }
}
