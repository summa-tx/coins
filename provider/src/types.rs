use coins_core::ser::{ByteFormat, SerError};

/// A minimal type representing a raw Bitcoin header.
#[derive(Copy, Clone)]
pub struct RawHeader([u8; 80]);

impl Default for RawHeader {
    fn default() -> Self {
        Self([0u8; 80])
    }
}

impl From<[u8; 80]> for RawHeader {
    fn from(buf: [u8; 80]) -> Self {
        Self(buf)
    }
}

impl AsRef<[u8; 80]> for RawHeader {
    fn as_ref(&self) -> &[u8; 80] {
        &self.0
    }
}

impl AsMut<[u8; 80]> for RawHeader {
    fn as_mut(&mut self) -> &mut [u8; 80] {
        &mut self.0
    }
}

impl ByteFormat for RawHeader {
    type Error = SerError;

    fn serialized_length(&self) -> usize {
        80
    }

    fn read_from<R>(reader: &mut R) -> Result<Self, Self::Error>
    where
        R: std::io::Read,
        Self: std::marker::Sized,
    {
        let mut header = [0u8; 80];
        reader.read_exact(&mut header)?;
        Ok(header.into())
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: std::io::Write,
    {
        writer.write_all(self.as_ref())?;
        Ok(80)
    }
}
