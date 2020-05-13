//! A simple trait for binary (de)Serialization using std `Read` and `Write` traits.

use base64::DecodeError;
use bitcoin_spv::types::Hash256Digest;
use hex::FromHexError;
use std::{
    fmt::Debug,
    io::{Cursor, Error as IOError, Read, Write},
};
use thiserror::Error;

/// Erros related to serialization of types.
#[derive(Debug, Error)]
pub enum SerError {
    /// VarInts must be minimal.
    #[error("Attempted to deserialize non-minmal VarInt. Someone is doing something fishy.")]
    NonMinimalVarInt,

    /// IOError bubbled up from a `Write` passed to a `Ser::write_to` implementation.
    #[error(transparent)]
    IOError(#[from] IOError),

    /// `deserialize_hex` encountered an error on its input.
    #[error(transparent)]
    FromHexError(#[from] FromHexError),

    /// `deserialize_base64` encountered an error on its input.
    #[error(transparent)]
    DecodeError(#[from] DecodeError),

    /// An error by a component call in data structure (de)serialization
    #[error("Error in component (de)serialization: {0}")]
    ComponentError(String),

    /// Failed to pass a limit to an iterated deserializer that requires one.
    #[error("Deserialization of this struct needs additional lenght information")]
    RequiresLimit,
}

/// Type alias for serialization errors
pub type SerResult<T> = Result<T, SerError>;

/// Calculates the minimum prefix length for a VarInt encoding `number`
pub fn prefix_byte_len(number: u64) -> u8 {
    match number {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Matches the length of the VarInt to the 1-byte flag
pub fn first_byte_from_len(number: u8) -> Option<u8> {
    match number {
        3 => Some(0xfd),
        5 => Some(0xfe),
        9 => Some(0xff),
        _ => None,
    }
}

/// Matches the VarInt prefix flag to the serialized length
pub fn prefix_len_from_first_byte(number: u8) -> u8 {
    match number {
        0..=0xfc => 1,
        0xfd => 3,
        0xfe => 5,
        0xff => 9,
    }
}

/// Convenience function for writing a Bitcoin-style VarInt
pub fn write_compact_int<W>(writer: &mut W, number: u64) -> Result<usize, SerError>
where
    W: Write,
{
    let prefix_len = prefix_byte_len(number);
    let written: usize = match first_byte_from_len(prefix_len) {
        None => writer.write(&[number as u8])?,
        Some(prefix) => {
            let mut written = writer.write(&[prefix])?;
            let body = (number as u64).to_le_bytes();
            written += writer.write(&body[..prefix_len as usize - 1])?;
            written
        }
    };
    Ok(written)
}

/// Convenience function for reading a Bitcoin-style VarInt
pub fn read_compact_int<R>(reader: &mut R) -> Result<u64, SerError>
where
    R: Read,
{
    let mut prefix = [0u8; 1];
    reader.read_exact(&mut prefix)?; // read at most one byte
    let prefix_len = prefix_len_from_first_byte(prefix[0]);

    // Get the byte(s) representing the number, and parse as u64
    let number = if prefix_len > 1 {
        let mut buf = [0u8; 8];
        let mut body = reader.take(prefix_len as u64 - 1); // minus 1 to account for prefix
        let _ = body.read(&mut buf)?;
        u64::from_le_bytes(buf)
    } else {
        prefix[0] as u64
    };

    let minimal_length = prefix_byte_len(number);
    if minimal_length < prefix_len {
        Err(SerError::NonMinimalVarInt)
    } else {
        Ok(number)
    }
}

/// A simple trait for deserializing from `std::io::Read` and serializing to `std::io::Write`.
/// We have provided implementations for `u8` and `Vec<T: Ser>`
///
/// `Ser` is used extensively in Sighash calculation, txid calculations, and transaction
/// serialization and deserialization.
pub trait ByteFormat {
    /// An associated error type
    type Error: From<SerError> + From<IOError> + std::error::Error;

    /// Returns the byte-length of the serialized data structure.
    fn serialized_length(&self) -> usize;

    /// Convenience function for reading a LE u32
    fn read_u32_le<R>(reader: &mut R) -> Result<u32, Self::Error>
    where
        R: Read,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Convenience function for reading a LE u64
    fn read_u64_le<R>(reader: &mut R) -> Result<u64, Self::Error>
    where
        R: Read,
    {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Convenience function for reading a Bitcoin-style VarInt
    fn read_compact_int<R>(reader: &mut R) -> Result<u64, <Self as ByteFormat>::Error>
    where
        R: Read,
    {
        read_compact_int(reader).map_err(Into::into)
    }

    /// Convenience function for reading a prefixed vector
    fn read_prefix_vec<R, E, I>(reader: &mut R) -> Result<Vec<I>, <Self as ByteFormat>::Error>
    where
        R: Read,
        E: Into<Self::Error> + From<SerError> + From<IOError> + std::error::Error,
        I: ByteFormat<Error = E>,
    {
        let items = Self::read_compact_int(reader)?;
        let mut ret = vec![];
        for _ in 0..items {
            ret.push(I::read_from(reader, 0).map_err(Into::into)?);
        }
        Ok(ret)
    }

    /// Convenience function for writing a LE u32
    fn write_u32_le<W>(writer: &mut W, number: u32) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write,
    {
        Ok(writer.write(&number.to_le_bytes())?)
    }

    /// Convenience function for writing a LE u64
    fn write_u64_le<W>(writer: &mut W, number: u64) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write,
    {
        Ok(writer.write(&number.to_le_bytes())?)
    }

    /// Convenience function for writing a Bitcoin-style VarInt
    fn write_compact_int<W>(
        writer: &mut W,
        number: u64,
    ) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write,
    {
        write_compact_int(writer, number).map_err(Into::into)
    }

    /// Convenience function to write a length-prefixed vector.
    fn write_prefix_vec<W, E, I>(
        writer: &mut W,
        vector: &[I],
    ) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write,
        E: Into<Self::Error> + From<SerError> + From<IOError> + std::error::Error,
        I: ByteFormat<Error = E>,
    {
        let mut written = Self::write_compact_int(writer, vector.len() as u64)?;
        for i in vector.iter() {
            written += i.write_to(writer).map_err(Into::into)?;
        }
        Ok(written)
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
    /// let result = Hash256Digest::read_from(&mut a.as_ref(), 0).unwrap();
    ///
    /// assert_eq!(result, Hash256Digest::default());
    ///
    /// let mut b = [0u8; 32];
    /// let result = Vec::<u8>::read_from(&mut b.as_ref(), 16).unwrap();
    ///
    /// assert_eq!(result, vec![0u8; 16]);
    /// ```
    fn read_from<R>(reader: &mut R, limit: usize) -> Result<Self, Self::Error>
    where
        R: Read,
        Self: std::marker::Sized;

    /// Decodes a hex string to a `Vec<u8>`, deserializes an instance of `Self` from that vector.
    fn deserialize_hex(s: &str) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        let v: Vec<u8> = hex::decode(s).map_err(SerError::from)?;
        let mut cursor = Cursor::new(v);
        Self::read_from(&mut cursor, 0)
    }

    /// Serialize `self` to a base64 string, using standard RFC4648 non-url safe characters
    fn deserialize_base64(s: &str) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        let v: Vec<u8> = base64::decode(s).map_err(SerError::from)?;
        let mut cursor = Cursor::new(v);
        Self::read_from(&mut cursor, 0)
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
    /// let written = Hash256Digest::default().write_to(&mut buf).unwrap();
    ///
    /// assert_eq!(
    ///    buf,
    ///    vec![0u8; 32]
    /// );
    /// ```
    fn write_to<W>(&self, writer: &mut W) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write;

    /// Serializes `self` to a vector, returns the hex-encoded vector
    fn serialize_hex(&self) -> Result<String, <Self as ByteFormat>::Error> {
        let mut v: Vec<u8> = vec![];
        self.write_to(&mut v)?;
        Ok(hex::encode(v))
    }

    /// Serialize `self` to a base64 string, using standard RFC4648 non-url safe characters
    fn serialize_base64(&self) -> Result<String, <Self as ByteFormat>::Error> {
        let mut v: Vec<u8> = vec![];
        self.write_to(&mut v)?;
        Ok(base64::encode(v))
    }
}

impl<E, I> ByteFormat for Vec<I>
where
    E: From<SerError> + From<IOError> + std::error::Error,
    I: ByteFormat<Error = E>,
{
    type Error = E;

    fn serialized_length(&self) -> usize {
        self.iter().map(|v| v.serialized_length()).sum()
    }

    fn read_from<T>(reader: &mut T, limit: usize) -> Result<Self, Self::Error>
    where
        T: Read,
        Self: std::marker::Sized,
    {
        let mut v = vec![];
        for _ in 0..limit {
            v.push(I::read_from(reader, 0)?);
        }
        Ok(v)
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write,
    {
        Ok(self.iter().map(|v| v.write_to(writer).unwrap()).sum())
    }
}

impl ByteFormat for Hash256Digest {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        32
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let mut buf = Hash256Digest::default();
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
    {
        Ok(writer.write(self)?)
    }
}

impl ByteFormat for u8 {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        1
    }

    fn read_from<R>(reader: &mut R, _limit: usize) -> SerResult<Self>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(u8::from_le_bytes(buf))
    }

    fn write_to<W>(&self, writer: &mut W) -> SerResult<usize>
    where
        W: Write,
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
            (0xffff_ffff_ffff_ffff, 9, Some(0xff)),
        ];
        for case in cases.iter() {
            assert_eq!(prefix_byte_len(case.0), case.1);
            assert_eq!(first_byte_from_len(case.1), case.2);
        }
    }
}
