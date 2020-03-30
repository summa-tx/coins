//! A simple trait for binary (de)Serialization using std `Read` and `Write` traits.

use std::io::{Read, Write, Error as IOError, Cursor};
use hex::FromHexError;

use thiserror::Error;
use bitcoin_spv::types::Hash256Digest;


/// Erros related to serialization of types.
#[derive(Debug, Error)]
pub enum SerError{
    /// VarInts must be 1, 3, 5, or 9 bytes long
    #[error("Bad VarInt length. Must be 1,3,5, or 9. Got {:?}.", .0)]
    BadVarIntLen(u8),

    /// Tried to add more inputs to a prefix vector, but the var int serialized length couldn't
    /// be incremented.
    #[error("VarInt length too short. Got {:?}. Need at least {:?} bytes.", .got, .need)]
    VarIntTooShort{
        /// The current VarInt length for `push_item()` operations. The proposed new length
        /// for `set_prefix_len()` operations.
        got: u8,
        /// The minimum necessary VarInt length
        need: u8
    },

    /// IOError bubbled up from a `Write` passed to a `Ser::serialize` implementation.
    #[error("Serialization error")]
    IOError(#[from] IOError),

    /// Got an unknown flag where we expected a witness flag. May indicate a non-witness
    /// transaction.
    #[error("Witness flag not as expected. Got {:?}. Expected {:?}.", .0, [0u8, 1u8])]
    BadWitnessFlag([u8; 2]),

    /// `deserialize_hex` encountered an error on its input.
    #[error("Error deserializing hex string")]
    FromHexError(#[from] FromHexError),
}

/// Type alias for serialization errors
pub type SerResult<T> = Result<T, SerError>;

/// A simple trait for deserializing from `std::io::Read` and serializing to `std::io::Write`.
/// We have provided implementations for `u8` and `Vec<T: Ser>`
///
/// `Ser` is used extensively in Sighash calculation, txid calculations, and transaction
/// serialization and deserialization.
pub trait Ser {

    /// Returns a JSON string with the serialized data structure. We do not yet implement
    /// `from_json`.
    fn to_json(&self) -> String;

    /// Returns the byte-length of the serialized data structure.
    fn serialized_length(&self) -> usize;

    /// Convenience function for reading a LE u32
    fn read_u32_le<R>(reader: &mut R) -> SerResult<u32>
    where
        R: Read
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Convenience function for reading a LE u64
    fn read_u64_le<R>(reader: &mut R) -> SerResult<u64>
    where
        R: Read
    {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Convenience function for writing a LE u32
    fn write_u32_le<W>(writer: &mut W, number: u32) -> SerResult<usize>
    where
        W: Write
    {
        Ok(writer.write(&number.to_le_bytes())?)
    }

    /// Convenience function for writing a LE u64
    fn write_u64_le<W>(writer: &mut W, number: u64) -> SerResult<usize>
    where
        W: Write
    {
        Ok(writer.write(&number.to_le_bytes())?)
    }

    /// Deserializes an instance of `Self` from a `std::io::Read`.
    /// The `limit` argument is used only when deserializing collections, and  specifies a maximum
    /// number of instances of the underlying type to read.
    ///
    /// ```
    /// use std::io::Read;
    /// use riemann_core::ser::*;
    /// use bitcoin_spv::types::Hash256Digest;
    ///
    /// let mut a = [0u8; 32];
    /// let result = Hash256Digest::deserialize(&mut a.as_ref(), 0).unwrap();
    ///
    /// assert_eq!(result, Hash256Digest::default());
    ///
    /// let mut b = [0u8; 32];
    /// let result = Vec::<u8>::deserialize(&mut b.as_ref(), 16).unwrap();
    ///
    /// assert_eq!(result, vec![0u8; 16]);
    /// ```
    fn deserialize<R>(reader: &mut R, limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized;

    /// Decodes a hex string to a `Vec<u8>`, deserializes an instance of `Self` from that vector.
    fn deserialize_hex(s: String) -> SerResult<Self>
    where
        Self: std::marker::Sized
    {
        let v: Vec<u8> = hex::decode(s)?;
        let mut cursor = Cursor::new(v);
        Self::deserialize(&mut cursor, 0)
    }

    /// Serializes `Self` to a `std::io::Write`. Following `Write` trait conventions, its `Ok`
    /// type is a `usize` denoting the number of bytes written.
    ///
    /// ```
    /// use std::io::Write;
    /// use riemann_core::ser::*;
    /// use bitcoin_spv::types::Hash256Digest;
    ///
    /// let mut buf: Vec<u8> = vec![];
    /// let written = Hash256Digest::default().serialize(&mut buf).unwrap();
    ///
    /// assert_eq!(
    ///    buf,
    ///    vec![0u8; 32]
    /// );
    /// ```
    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write;

    /// Serializes `self` to a vector, returns the hex-encoded vector
    fn serialize_hex(&self) -> SerResult<String> {
        let mut v: Vec<u8> = vec![];
        self.serialize(&mut v)?;
        Ok(hex::encode(v))
    }
}

impl<A: Ser> Ser for Vec<A> {

    fn to_json(&self) -> String {
        let items: Vec<String> = self.iter().map(Ser::to_json).collect();
        format!("[{}]", &items[..].join(", "))
    }

    fn serialized_length(&self) -> usize {
        self.iter().map(|v| v.serialized_length()).sum()
    }

    fn deserialize<T>(reader: &mut T, limit: usize) -> SerResult<Self>
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

    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write
    {
        Ok(self.iter().map(|v| v.serialize(writer).unwrap()).sum())
    }
}

impl Ser for Hash256Digest {
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
        let mut buf = Hash256Digest::default();
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn serialize<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write
    {
        Ok(writer.write(self)?)
    }
}
