use std::ops::{Index, IndexMut};
use std::io::{Read, Write, Error as IOError, Cursor};
// use std::iter::{Extend};

use bitcoin_spv::types::Hash256Digest;

use thiserror::Error;

/// An Error type for transaction objects
#[derive(Debug, Error)]
pub enum TxError{
    /// IOError bubbled up from a `Write` passed to a `Ser::serialize` implementation.
    #[error("Serialization error")]
    IOError(#[from] IOError),

    /// VarInts must be 1, 3, 5, or 9 bytes long
    #[error("Bad VarInt length. Must be 1,3,5, or 9. Got {:?}.", .0)]
    BadVarIntLen(u8),

    /// Tried to add more inputs to a prefix vector, but the var int serialized length couldn't
    /// be incremented.
    #[error("VarInt length too short. Got {:?}. Need at least {:?} bytes.", .got, .need)]
    VarIntTooShort{got: u8, need: u8},

    /// Got an unknown flag where we expected a witness flag. May indicate a non-witness
    /// transaction.
    #[error("Witness flag not as expected. Got {:?}. Expected {:?}.", .0, [0u8, 1u8])]
    BadWitnessFlag([u8; 2]),

    /// Sighash NONE is unsupported
    #[error("SIGHASH_NONE is unsupported")]
    NoneUnsupported,

    /// Satoshi's sighash single bug. Throws an error here.
    #[error("SIGHASH_SINGLE bug is unsupported")]
    SighashSingleBug,

    // /// No inputs in vin
    // #[error("Vin may not be empty")]
    // EmptyVin,
    //
    // /// No outputs in vout
    // #[error("Vout may not be empty")]
    // EmptyVout
}

/// Type alias for result with TxError
pub type TxResult<T> = Result<T, TxError>;

/// A simple trait for deserializing from `std::io::Read` and serializing to `std::io::Write`.
/// We have provided implementations that write LE u8, u32, and u64, and several other basic
/// types. Bitcoin doesn't use u16, so we have left that unimplemented.
///
/// `Ser` is used extensively in Sighash calculation, txid calculations, and transaction
/// serialization and deserialization.
pub trait Ser {

    /// Returns the byte-length of the serialized data structure.
    fn serialized_length(&self) -> usize;

    /// Deserializes an instance of `Self` from a `std::io::Read`
    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized;

    /// Decodes a hex string to a vector, deserializes an instance of `Self` from that vector
    ///
    /// TODO: Can panic if the string is non-hex.
    fn deserialize_hex(s: String) -> TxResult<Self>
    where
        Self: std::marker::Sized
    {
        let v: Vec<u8> = hex::decode(s).unwrap();
        let mut cursor = Cursor::new(v);
        Ok(Self::deserialize(&mut cursor, 0)?)
    }

    /// Serializes `Self` to a `std::io::Write`
    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
    where
        W: Write;

    /// Serializes `self` to a vector, returns the hex-encoded vector
    fn serialize_hex(&self) -> TxResult<String> {
        let mut v: Vec<u8> = vec![];
        self.serialize(&mut v)?;
        Ok(hex::encode(v))
    }
}

impl<A: Ser> Ser for Vec<A> {
    fn serialized_length(&self) -> usize {
        // panics. TODO: fix later
        self.iter().map(|v| v.serialized_length()).sum()
    }

    fn deserialize<T>(reader: &mut T, limit: usize) -> TxResult<Self>
    where
        T: Read,
        Self: std::marker::Sized
    {
        let mut v = vec![];
        for _ in 0..limit {
            v.push(A::deserialize(reader, 0)?);
        }
        Ok(v)
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
    where
        W: Write
    {
        Ok(self.iter().map(|v| v.serialize(writer).unwrap()).sum())
    }
}

impl Ser for Hash256Digest {
    fn serialized_length(&self) -> usize {
        32
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = Hash256Digest::default();
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
    where
        W: Write
    {
        Ok(writer.write(self)?)
    }
}

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
/// TODO: change set_items into push_item.
pub trait PrefixVec {
    /// The Item that the represented vector contains.
    type Item;

    /// Construct an empty PrefixVec instance.
    fn null() -> Self;

    fn set_items(&mut self, v: Vec<Self::Item>) -> TxResult<()>;
    fn set_prefix_len(&mut self, prefix_len: u8) -> TxResult<()>;

    fn push(&mut self, i: Self::Item);

    fn len(&self) -> usize;
    fn len_prefix(&self) -> u8;
    fn items(&self) -> &[Self::Item];

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn is_minimal(&self) -> bool {
        self.len_prefix() == prefix_byte_len(self.len() as u64)
    }

    fn is_sufficient(&self, length: usize) -> bool {
        sufficient_prefix(self.len_prefix(), length)
    }

    fn new(v: Vec<Self::Item>) -> Self
    where
        Self: std::marker::Sized
     {
        let mut s = Self::null();
        s.set_prefix_len(prefix_byte_len(v.len() as u64)).expect("Can't fail, as self is empty");
        s.set_items(v).expect("Can't fail, as prefix is set high enough.");
        s
    }

    fn new_non_minimal(v: Vec<Self::Item>, prefix_bytes: u8) -> TxResult<Self>
    where
        Self: Sized
    {
        match prefix_bytes {
            1 | 3 | 5 | 9 => {
                let mut s = Self::null();
                s.set_prefix_len(prefix_bytes)?;
                s.set_items(v).expect("");
                Ok(s)
            },
            _ => Err(TxError::BadVarIntLen(prefix_bytes))
        }
    }
}

impl<T, I> Ser for T
where
    T: PrefixVec<Item = I>,
    I: Ser,
{
    fn serialized_length(&self) -> usize {
        let mut length = self.items().iter().map(|v| v.serialized_length()).sum();
        length += self.len_prefix() as usize;
        length
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<T>
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

        let vec = Vec::<I>::deserialize(reader, expected_vector_length as usize)?;
        Ok(T::new_non_minimal(vec, prefix_len)?)
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
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
        let writes: TxResult<Vec<usize>> = self.items()
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

impl<T> PrefixVec for ConcretePrefixVec<T>
{
    type Item = T;

    fn null() -> Self {
        Self{
            prefix_bytes: 1,
            items: vec![]
        }
    }

    fn set_items(&mut self, v: Vec<T>) -> TxResult<()> {
        if !self.is_sufficient(v.len()) {
            return Err(
                TxError::VarIntTooShort{
                    got: self.prefix_bytes,
                    need: prefix_byte_len(v.len() as u64)
                }
            );
        };
        self.items = v;
        Ok(())
    }

    fn set_prefix_len(&mut self, prefix_bytes: u8) -> TxResult<()> {
        if !sufficient_prefix(prefix_bytes, self.len()) {
            return Err(
                TxError::VarIntTooShort{
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

impl<T, U> From<U> for ConcretePrefixVec<T>
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

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(u8::from_le_bytes(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
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

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
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

    fn deserialize<R>(reader: &mut R, _limit: usize) -> TxResult<Self>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn serialize<W>(&self, writer: &mut W) -> TxResult<usize>
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
