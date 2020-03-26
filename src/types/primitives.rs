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

/// Determines whether `prefix_bytes` bytes is sufficient to encode `number` in a VarInt
pub fn sufficient_prefix(prefix_bytes: u8, number: usize) -> bool {
    let req = prefix_byte_len(number as u64);
    prefix_bytes >= req
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

    /// Set the underlying items vector. This must also either set the `prefix_len`, or error if
    /// the prefix_len is insufficient to encode the new item vector length.
    fn set_items(&mut self, v: Vec<Self::Item>) -> SerResult<()>;

    /// Set the prefix length. This shoumust error if the new length is insufficent to encode the
    /// current item vector length.
    fn set_prefix_len(&mut self, prefix_len: u8) -> SerResult<()>;

    /// Push an item to the item vector.
    fn push(&mut self, i: Self::Item);

    /// Return the length of the item vector.
    fn len(&self) -> usize;

    /// Return the encoded length of the VarInt prefix.
    fn len_prefix(&self) -> u8;

    /// Return a reference to the contents of the item vector.
    fn items(&self) -> &[Self::Item];

    /// Return true if the length of the item vector is 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return false if the length of the item vector could be represented by a smaller VarInt.
    fn is_minimal(&self) -> bool {
        self.len_prefix() == prefix_byte_len(self.len() as u64)
    }

    /// Return true if the current `prefix_len` can encode `length`. False otherwise.
    fn is_sufficient(&self, length: usize) -> bool {
        sufficient_prefix(self.len_prefix(), length)
    }

    /// Instantiate a new `PrefixVec` that contains v.
    fn new(v: Vec<Self::Item>) -> Self
    where
        Self: std::marker::Sized
     {
        let mut s = Self::null();
        s.set_prefix_len(prefix_byte_len(v.len() as u64)).expect("Can't fail, as self is empty");
        s.set_items(v).expect("Can't fail, as prefix is set high enough.");
        s
    }

    /// Instantiate a new `PrefixVec` that contains `v` and has a non-minimal `VarInt` prefix.
    fn new_non_minimal(v: Vec<Self::Item>, prefix_bytes: u8) -> SerResult<Self>
    where
        Self: Sized
    {
        // TODO: this can cause bad state. Need to check sufficient.
        match prefix_bytes {
            1 | 3 | 5 | 9 => {
                let mut s = Self::null();
                s.set_prefix_len(prefix_bytes)?;
                s.set_items(v).expect("");
                Ok(s)
            },
            _ => Err(SerError::BadVarIntLen(prefix_bytes))
        }
    }
}

impl<T, I> Ser for T
where
    I: Ser,
    T: PrefixVec<Item = I>,
{
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

        // Get the bytes representing the vector length
        let expected_vector_length = if prefix_len > 1{
            let mut buf = [0u8; 8];
            let mut body = reader.take(prefix_len as u64 - 1); // minus 1 to account for prefix
            let _ = body.read(&mut buf)?;
            u64::from_le_bytes(buf)
        } else {
            prefix[0] as u64
        };

        let vec = Vec::<<T as PrefixVec>::Item>::deserialize(reader, expected_vector_length as usize)?;
        Ok(T::new_non_minimal(vec, prefix_len)?)
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
        // Ok(written)
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
///
/// ConcretePrefixVec tracks the expected serialized length of its prefix, and allows non-minimal
/// VarInts. If the vector length can't be serialized in that number of bytes the current prefix,
/// an error will be returned.
///
/// TODO: `impl<T> Into<Iter> for &ConcretePrefixVec<T>
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConcretePrefixVec<T> {
    prefix_bytes: u8,
    items: Vec<T>
}

impl<T: Ser> PrefixVec for ConcretePrefixVec<T>
{
    type Item = T;

    fn null() -> Self {
        Self{
            prefix_bytes: 1,
            items: vec![]
        }
    }

    fn set_items(&mut self, v: Vec<T>) -> SerResult<()> {
        if !self.is_sufficient(v.len()) {
            return Err(
                SerError::VarIntTooShort{
                    got: self.prefix_bytes,
                    need: prefix_byte_len(v.len() as u64)
                }
            );
        };
        self.items = v;
        Ok(())
    }

    fn set_prefix_len(&mut self, prefix_bytes: u8) -> SerResult<()> {
        if !sufficient_prefix(prefix_bytes, self.len()) {
            return Err(
                SerError::VarIntTooShort{
                    got: prefix_bytes,
                    need: prefix_byte_len(self.len() as u64)
                }
            );
        };
        self.prefix_bytes = prefix_bytes;
        Ok(())
    }

    fn push(&mut self, i: Self::Item) {
        self.items.push(i)
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn len_prefix(&self) -> u8 {
        self.prefix_bytes
    }

    fn items(&self) -> &[T] {
        &self.items
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
        &self.items[index]
    }
}

impl<T> IndexMut<usize> for ConcretePrefixVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.items[index]
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
        self.items.extend(iter)
    }
}

impl Ser for u8 {
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

impl Ser for u32 {
    fn serialized_length(&self) -> usize {
        4
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write
    {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl Ser for u64 {
    fn serialized_length(&self) -> usize {
        8
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
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
