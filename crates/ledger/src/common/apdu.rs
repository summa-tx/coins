use std::fmt;

/// A write would exceed [`ApduBuffer::CAPACITY`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ApduBuffer capacity exceeded")]
pub struct BufferFull;

#[derive(Copy, Clone, Eq)]
/// A buffer holding one APDU command or response.
pub struct ApduBuffer {
    len: u16,
    data: [u8; 261],
}

impl Default for ApduBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for ApduBuffer {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl fmt::Debug for ApduBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApduBuffer")
            .field("bytes", &self.len)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for ApduBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[..self.len as usize]
    }
}

impl AsRef<[u8]> for ApduBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl std::ops::DerefMut for ApduBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let len = self.len as usize;
        &mut self.data[..len]
    }
}

impl ApduBuffer {
    /// The number of bytes the buffer can hold.
    pub const CAPACITY: usize = 261;

    /// An empty buffer.
    pub const fn new() -> Self {
        Self {
            len: 0,
            data: [0; Self::CAPACITY],
        }
    }

    /// The length of the buffer.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// True if the buffer is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Shorten the buffer to `len` bytes. Does nothing if it is already
    /// shorter.
    pub const fn truncate(&mut self, len: usize) {
        if len < self.len as usize {
            self.len = len as u16;
        }
    }

    /// Clear the buffer for reuse.
    pub const fn clear(&mut self) {
        self.len = 0
    }

    /// The number of bytes that can still be appended.
    pub const fn remaining_capacity(&self) -> usize {
        Self::CAPACITY - self.len as usize
    }

    /// Append `bytes`. Fails, leaving the buffer unchanged, if they do not
    /// fit.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), BufferFull> {
        if bytes.len() > self.remaining_capacity() {
            return Err(BufferFull);
        }
        let start = self.len as usize;
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len() as u16;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../ai-tests/common/apdu.rs"]
mod ai_tests;
