//! A simple trait for binary (de)Serialization using std `Read` and `Write` traits.

use std::io::{Read, Write, Error as IOError, Cursor};

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
}

/// Type alias for serialization errors
pub type SerResult<T> = Result<T, SerError>;

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
    fn deserialize<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized;

    /// Decodes a hex string to a vector, deserializes an instance of `Self` from that vector
    ///
    /// TODO: Can panic if the string is non-hex.
    fn deserialize_hex(s: String) -> SerResult<Self>
    where
        Self: std::marker::Sized
    {
        let v: Vec<u8> = hex::decode(s).unwrap();
        let mut cursor = Cursor::new(v);
        Self::deserialize(&mut cursor, 0)
    }

    /// Serializes `Self` to a `std::io::Write`
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
    fn serialized_length(&self) -> usize {
        // panics. TODO: fix later
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
