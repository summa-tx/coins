use std::fmt;

use crate::{common::ApduBuffer, errors::LedgerError};

/// Builds an [`ApduCommand`]. `cla` and `ins` are required; `p1` and `p2`
/// default to zero.
///
/// ```
/// # use coins_ledger::common::CommandBuilder;
/// let cmd = CommandBuilder::new()
///     .cla(0xe0)
///     .ins(0x06)
///     .build()
///     .unwrap();
/// assert_eq!(cmd.as_bytes(), &[0xe0, 0x06, 0x00, 0x00]);
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandBuilder<'a> {
    cla: Option<u8>,
    ins: Option<u8>,
    p1: u8,
    p2: u8,
    le: Option<u8>,
    data: Option<&'a [u8]>,
}

impl<'a> CommandBuilder<'a> {
    /// Generate an empty builder.
    pub const fn new() -> Self {
        Self {
            cla: None,
            ins: None,
            p1: 0,
            p2: 0,
            le: None,
            data: None,
        }
    }

    /// Set the class byte. Required.
    pub const fn cla(mut self, cla: u8) -> Self {
        self.cla = Some(cla);
        self
    }

    /// Set the instruction byte. Required.
    pub const fn ins(mut self, ins: u8) -> Self {
        self.ins = Some(ins);
        self
    }

    /// Set instruction parameter 1.
    pub const fn p1(mut self, p1: u8) -> Self {
        self.p1 = p1;
        self
    }

    /// Set instruction parameter 2.
    pub const fn p2(mut self, p2: u8) -> Self {
        self.p2 = p2;
        self
    }

    /// Set the `Le` field.
    pub const fn le(mut self, le: u8) -> Self {
        self.le = Some(le);
        self
    }

    /// Set the data field. Length is checked at build.
    pub const fn data(mut self, data: &'a [u8]) -> Self {
        self.data = Some(data);
        self
    }

    /// Encode. Errors if `cla` or `ins` is unset or data exceeds
    /// [`ApduCommand::MAX_DATA_LEN`].
    pub fn build(self) -> Result<ApduCommand, LedgerError> {
        let cla = self.cla.ok_or(LedgerError::MissingCla)?;
        let ins = self.ins.ok_or(LedgerError::MissingIns)?;
        let mut command = ApduCommand(ApduBuffer::new());
        command.append(&[cla, ins, self.p1, self.p2]);
        if let Some(data) = self.data {
            command.set_data(data)?;
        }
        command.set_le(self.le);
        Ok(command)
    }
}

/// A short-form APDU command in wire encoding. Built by [`CommandBuilder`];
/// editable in place with the `set_*` methods.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ApduCommand(ApduBuffer);

impl fmt::Debug for ApduCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApduCommand")
            .field("cla", &format_args!("{:#04x}", self.cla()))
            .field("ins", &format_args!("{:#04x}", self.ins()))
            .field("p1", &format_args!("{:#04x}", self.p1()))
            .field("p2", &format_args!("{:#04x}", self.p2()))
            .field("data", &hex::encode(self.data()))
            .field("le", &self.le())
            .finish()
    }
}

impl std::ops::Deref for ApduCommand {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ApduCommand {
    /// The maximum data length of a short APDU.
    pub const MAX_DATA_LEN: usize = 255;

    /// CLA, INS, P1, P2.
    const HEADER_LEN: usize = 4;

    /// An empty [`CommandBuilder`].
    pub const fn builder<'a>() -> CommandBuilder<'a> {
        CommandBuilder::new()
    }

    /// The class byte.
    pub fn cla(&self) -> u8 {
        self.0[0]
    }

    /// The instruction byte.
    pub fn ins(&self) -> u8 {
        self.0[1]
    }

    /// Instruction parameter 1.
    pub fn p1(&self) -> u8 {
        self.0[2]
    }

    /// Instruction parameter 2.
    pub fn p2(&self) -> u8 {
        self.0[3]
    }

    /// The data field. Empty if the command carries no data.
    pub fn data(&self) -> &[u8] {
        match self.lc() {
            Some(lc) => &self.0[Self::HEADER_LEN + 1..Self::HEADER_LEN + 1 + lc],
            None => &[],
        }
    }

    /// The `Le` field, if one was set.
    pub fn le(&self) -> Option<u8> {
        let le_at = match self.lc() {
            None => Self::HEADER_LEN,
            Some(lc) => Self::HEADER_LEN + 1 + lc,
        };
        (self.0.len() == le_at + 1).then(|| self.0[le_at])
    }

    /// The encoded command, ready for the wire.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Set the class byte.
    pub fn set_cla(&mut self, cla: u8) {
        self.0[0] = cla;
    }

    /// Set the instruction byte.
    pub fn set_ins(&mut self, ins: u8) {
        self.0[1] = ins;
    }

    /// Set instruction parameter 1.
    pub fn set_p1(&mut self, p1: u8) {
        self.0[2] = p1;
    }

    /// Set instruction parameter 2.
    pub fn set_p2(&mut self, p2: u8) {
        self.0[3] = p2;
    }

    /// Replace the data field, keeping header and `Le`. Errors, changing
    /// nothing, if `data` exceeds [`ApduCommand::MAX_DATA_LEN`].
    pub fn set_data(&mut self, data: &[u8]) -> Result<(), LedgerError> {
        if data.len() > Self::MAX_DATA_LEN {
            return Err(LedgerError::DataTooLong(data.len()));
        }
        let le = self.le();
        self.0.truncate(Self::HEADER_LEN);
        if !data.is_empty() {
            self.append(&[data.len() as u8]);
            self.append(data);
        }
        if let Some(le) = le {
            self.append(&[le]);
        }
        Ok(())
    }

    /// Set or clear the `Le` field.
    pub fn set_le(&mut self, le: Option<u8>) {
        if self.le().is_some() {
            let len = self.0.len();
            self.0.truncate(len - 1);
        }
        if let Some(le) = le {
            self.append(&[le]);
        }
    }

    /// `Lc`, if the command carries data.
    fn lc(&self) -> Option<usize> {
        (self.0.len() > Self::HEADER_LEN + 1).then(|| self.0[Self::HEADER_LEN] as usize)
    }

    fn append(&mut self, bytes: &[u8]) {
        self.0
            .extend_from_slice(bytes)
            .expect("an encoded short APDU never exceeds ApduBuffer capacity");
    }
}

#[cfg(test)]
#[path = "../../ai-tests/common/command.rs"]
mod ai_tests;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize() {
        let data: &[u8] = &[0, 0, 0, 1, 0, 0, 0, 1];

        let command = CommandBuilder::new()
            .cla(0xe0)
            .ins(0x01)
            .data(data)
            .build()
            .unwrap();
        let expected: &[u8] = &[224, 1, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(command.as_bytes(), expected);

        let mut command = command;
        command.set_le(Some(13));
        let expected: &[u8] = &[224, 1, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 1, 13];
        assert_eq!(command.as_bytes(), expected);
    }
}
