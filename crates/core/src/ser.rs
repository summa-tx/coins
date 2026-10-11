//! A simple trait for binary (de)Serialization using std `Read` and `Write` traits.

use base64::{prelude::*, DecodeError};
use hex::FromHexError;
use std::{
    fmt::Debug,
    io::{Cursor, Error as IOError, Read, Write},
    vec,
};
use thiserror::Error;

/// Erros related to serialization of types.
#[derive(Debug, Error)]
pub enum SerError {
    /// IoError bubbled up from a `Write` passed to a `ByteFormat::write_to` implementation.
    #[error(transparent)]
    IoError(#[from] IOError),

    /// `deserialize_hex` encountered an error on its input.
    #[error(transparent)]
    FromHexError(#[from] FromHexError),

    /// `deserialize_base64` encountered an error on its input.
    #[error(transparent)]
    DecodeError(#[from] DecodeError),

    /// An error by a component call in data structure (de)serialization
    #[error("Error in component (de)serialization: {0}")]
    ComponentError(String),

    /// Thrown when `ReadSeqMode::Exactly` reads fewer items than expected.
    #[error("Expected a sequence of exaclty {expected} items. Got only {got} items")]
    InsufficientSeqItems {
        /// The number of items expected
        expected: usize,
        /// The number of items succesfully deserialized
        got: usize,
    },
}

/// Operation mode for `read_seq_from`.
pub enum ReadSeqMode {
    /// Specify `Exactly` to deserialize an exact number, or return an error
    Exactly(usize),
    /// Specify `AtMost` to stop deserializing at a specific number.
    AtMost(usize),
    /// Specify `UntilEnd` to read to the end of the reader.
    UntilEnd,
}

/// Type alias for serialization errors
pub type SerResult<T> = Result<T, SerError>;

/// Convenience function for reading a LE u32
pub fn read_u32_le<R>(reader: &mut R) -> SerResult<u32>
where
    R: Read,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Convenience function for writing a LE u32
pub fn write_u32_le<W>(writer: &mut W, number: u32) -> SerResult<usize>
where
    W: Write,
{
    Ok(writer.write(&number.to_le_bytes())?)
}

/// Convenience function for reading a LE u64
pub fn read_u64_le<R>(reader: &mut R) -> SerResult<u64>
where
    R: Read,
{
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Convenience function for writing a LE u64
pub fn write_u64_le<W>(writer: &mut W, number: u64) -> SerResult<usize>
where
    W: Write,
{
    Ok(writer.write(&number.to_le_bytes())?)
}

/// A simple trait for deserializing from `std::io::Read` and serializing to `std::io::Write`.
///
/// `ByteFormat` is used extensively in Sighash calculation, txid calculations, and transaction
/// serialization and deserialization.
pub trait ByteFormat {
    /// An associated error type
    type Error: From<SerError> + From<IOError> + std::error::Error;

    /// Returns the byte-length of the serialized data structure.
    fn serialized_length(&self) -> usize;

    /// Deserializes an instance of `Self` from a `std::io::Read`.
    /// The `limit` argument is used only when deserializing collections, and  specifies a maximum
    /// number of instances of the underlying type to read.
    ///
    /// ```
    /// use std::io::Read;
    /// use coins_core::{hashes::Hash256Digest, ser::*};
    ///
    /// let mut a = [0u8; 32];
    /// let result = Hash256Digest::read_from(&mut a.as_ref()).unwrap();
    ///
    /// assert_eq!(result, Hash256Digest::default());
    /// ```
    fn read_from<R>(reader: &mut R) -> Result<Self, Self::Error>
    where
        R: Read,
        Self: std::marker::Sized;

    /// Serializes `self` to a `std::io::Write`. Following `Write` trait conventions, its `Ok`
    /// type must be a `usize` denoting the number of bytes written.
    ///
    /// ```
    /// use std::io::Write;
    /// use coins_core::{hashes::Hash256Digest, ser::*};
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

    /// Read a sequence of objects from the reader. The mode argument specifies
    /// how many objects to read.
    fn read_seq_from<R>(reader: &mut R, mode: ReadSeqMode) -> Result<Vec<Self>, Self::Error>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        let mut v = vec![];
        match mode {
            ReadSeqMode::Exactly(number) => {
                for _ in 0..number {
                    v.push(Self::read_from(reader)?);
                }
                if v.len() != number {
                    return Err(SerError::InsufficientSeqItems {
                        got: v.len(),
                        expected: number,
                    }
                    .into());
                }
            }
            ReadSeqMode::AtMost(limit) => {
                for _ in 0..limit {
                    v.push(Self::read_from(reader)?);
                }
            }
            ReadSeqMode::UntilEnd => {
                while let Ok(obj) = Self::read_from(reader) {
                    v.push(obj);
                }
            }
        }
        Ok(v)
    }

    /// Write a sequence of `ByteFormat` objects to a writer. The `iter`
    /// argument may be any object that implements
    /// `IntoIterator<Item = &Item>`. This means we can seamlessly use vectors,
    /// slices, etc.
    ///
    /// ```
    /// use std::io::Write;
    /// use coins_core::{hashes::Hash256Digest, ser::*};
    ///
    /// let mut buf: Vec<u8> = vec![];
    /// let mut digests = vec![Hash256Digest::default(), Hash256Digest::default()];
    ///
    /// // Works with iterators
    /// let written = Hash256Digest::write_seq_to(&mut buf, digests.iter()).expect("Write succesful");
    ///
    /// assert_eq!(
    ///    buf,
    ///    vec![0u8; 64]
    /// );
    ///
    /// // And with vectors
    /// let written = Hash256Digest::write_seq_to(&mut buf, &digests).expect("Write succesful");
    /// assert_eq!(
    ///    buf,
    ///    vec![0u8; 128]
    /// );
    ///
    /// ```
    /// This should be invoked as `Item::write_seq_to(writer, iter)`
    fn write_seq_to<'a, W, E, Iter, Item>(
        writer: &mut W,
        iter: Iter,
    ) -> Result<usize, <Self as ByteFormat>::Error>
    where
        W: Write,
        E: Into<Self::Error> + From<SerError> + From<IOError> + std::error::Error,
        Item: 'a + ByteFormat<Error = E>,
        Iter: IntoIterator<Item = &'a Item>,
    {
        let mut written = 0;
        for item in iter {
            written += item.write_to(writer).map_err(Into::into)?;
        }
        Ok(written)
    }

    /// Decodes a hex string to a `Vec<u8>`, deserializes an instance of `Self` from that vector.
    fn deserialize_hex(s: &str) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        let v: Vec<u8> = hex::decode(s).map_err(SerError::from)?;
        let mut cursor = Cursor::new(v);
        Self::read_from(&mut cursor)
    }

    /// Serialize `self` to a base64 string, using standard RFC4648 non-url safe characters
    fn deserialize_base64(s: &str) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        let v: Vec<u8> = BASE64_STANDARD.decode(s).map_err(SerError::from)?;
        let mut cursor = Cursor::new(v);
        Self::read_from(&mut cursor)
    }

    /// Serializes `self` to a vector, returns the hex-encoded vector
    fn serialize_hex(&self) -> String {
        let mut v: Vec<u8> = vec![];
        self.write_to(&mut v).expect("No error on heap write");
        hex::encode(v)
    }

    /// Serialize `self` to a base64 string, using standard RFC4648 non-url safe characters
    fn serialize_base64(&self) -> String {
        let mut v: Vec<u8> = vec![];
        self.write_to(&mut v).expect("No error on heap write");
        BASE64_STANDARD.encode(v)
    }
}

impl ByteFormat for u8 {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        1
    }

    fn read_seq_from<R>(reader: &mut R, mode: ReadSeqMode) -> SerResult<Vec<u8>>
    where
        R: Read,
        Self: std::marker::Sized,
    {
        match mode {
            ReadSeqMode::Exactly(number) => {
                let mut v = vec![0u8; number];
                reader.read_exact(v.as_mut_slice())?;
                Ok(v)
            }
            ReadSeqMode::AtMost(limit) => {
                let mut v = vec![0u8; limit];
                let n = reader.read(v.as_mut_slice())?;
                v.truncate(n);
                Ok(v)
            }
            ReadSeqMode::UntilEnd => {
                let mut buf = vec![];
                reader.read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }

    fn read_from<R>(reader: &mut R) -> SerResult<Self>
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
    fn it_implements_byteformat_for_u8() {
        for i in 0..u8::MAX {
            let size = i.serialized_length();
            assert_eq!(size, 1);

            // `write_to` and `read_from`
            let mut v = vec![];
            i.write_to(&mut v).unwrap();
            let mut slice = v.as_slice();

            let expected = u8::read_from(&mut slice).unwrap();
            assert_eq!(i, expected);
        }
    }

    #[test]
    fn it_implements_seq_ops_for_u8() {
        let input = vec![0, 1, 2, 3, 4];
        let mut buf = vec![];
        u8::write_seq_to(&mut buf, input.iter()).unwrap();
        assert_eq!(buf.len(), input.len());
        assert_eq!(buf, input);

        // Read exactly the whole slice
        let exact_len =
            u8::read_seq_from(&mut buf.clone().as_slice(), ReadSeqMode::Exactly(buf.len()))
                .unwrap();
        assert_eq!(exact_len.len(), buf.len());
        assert_eq!(input, exact_len);

        // Try to read more than the size of the slice
        let exact_too_long = u8::read_seq_from(
            &mut buf.clone().as_slice(),
            ReadSeqMode::Exactly(buf.len() + 1),
        );
        assert!(exact_too_long.is_err());

        // Read exactly the first element
        let exact_first =
            u8::read_seq_from(&mut buf.clone().as_slice(), ReadSeqMode::Exactly(1)).unwrap();
        assert_eq!(exact_first, vec![0]);

        // Read exactly no elements
        let exact_none =
            u8::read_seq_from(&mut buf.clone().as_slice(), ReadSeqMode::Exactly(0)).unwrap();
        assert_eq!(exact_none, Vec::<u8>::new());

        // Read at most all of the elements
        let at_most_all =
            u8::read_seq_from(&mut buf.clone().as_slice(), ReadSeqMode::AtMost(buf.len())).unwrap();
        assert_eq!(at_most_all, buf.clone());
        //println!("{:?}", at_most)

        // Read at most 10 more elements than exist
        let at_most_more = u8::read_seq_from(
            &mut buf.clone().as_slice(),
            ReadSeqMode::AtMost(buf.len() + 10),
        )
        .unwrap();
        assert_eq!(at_most_more, buf.clone());

        // Read at most 1 less element than what exists
        let at_most_less = u8::read_seq_from(
            &mut buf.clone().as_slice(),
            ReadSeqMode::AtMost(buf.len() - 1),
        )
        .unwrap();
        let mut resized = buf.clone();
        resized.resize(buf.len() - 1, 0);
        assert_eq!(at_most_less, resized);

        // Read until the end
        let until_end =
            u8::read_seq_from(&mut buf.clone().as_slice(), ReadSeqMode::UntilEnd).unwrap();
        assert_eq!(until_end, buf.clone());
    }
}
