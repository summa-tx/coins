use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};
use tracing::{Span, field::display};

use crate::{
    Model,
    common::{ApduAnswer, ApduBuffer, ApduCommand},
    errors::LedgerError,
    transports::{DeviceIdentity, LedgerTransport, speculos::SpeculosError},
};

/// Where the connection stands between exchanges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The next exchange may proceed.
    Ready,
    /// A command was sent and its reply has not been consumed.
    #[allow(dead_code)] // Set once exchanges can time out.
    PendingReply,
    /// The stream is in an unknown state.
    Broken,
}

/// A transport to a Speculos emulator's APDU socket.
///
/// Speculos frames each APDU as a 4-byte big-endian length and the bytes.
/// Replies carry the length of their data, excluding the status word, then the
/// data, then the status word.
#[derive(Debug)]
pub struct SpeculosTransport {
    stream: TcpStream,
    model: Model,
    state: State,
    /// Bytes read from the socket but not yet framed.
    inbox: Vec<u8>,
}

impl SpeculosTransport {
    /// Connect to the APDU socket of a Speculos instance emulating `model`.
    pub async fn connect(addr: impl ToSocketAddrs, model: Model) -> Result<Self, SpeculosError> {
        Ok(Self {
            stream: TcpStream::connect(addr).await?,
            model,
            state: State::Ready,
            inbox: Vec::new(),
        })
    }

    /// Read one reply frame, keeping partial frames in `inbox`. Cancel-safe:
    /// dropping the future loses no bytes.
    async fn read_frame(&mut self) -> Result<ApduBuffer, SpeculosError> {
        loop {
            if let Some(header) = self.inbox.first_chunk::<4>() {
                let total = u32::from_be_bytes(*header) as usize + 2;
                if total > ApduBuffer::CAPACITY {
                    self.state = State::Broken;
                    return Err(SpeculosError::ResponseTooLong(total));
                }
                if self.inbox.len() >= 4 + total {
                    let mut buf = ApduBuffer::new();
                    buf.extend_from_slice(&self.inbox[4..4 + total])
                        .expect("length was checked against the capacity");
                    self.inbox.drain(..4 + total);
                    return Ok(buf);
                }
            }
            match self.stream.read_buf(&mut self.inbox).await {
                Ok(0) => {
                    self.state = State::Broken;
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                }
                Ok(_) => {}
                Err(e) => {
                    self.state = State::Broken;
                    return Err(e.into());
                }
            }
        }
    }
}

impl LedgerTransport for SpeculosTransport {
    fn identity(&self) -> Option<DeviceIdentity<'_>> {
        Some(DeviceIdentity::new(self.model, None))
    }

    async fn exchange(
        &mut self,
        command: ApduCommand,
        _timeout: Option<Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        if let Some(identity) = self.identity() {
            Span::current().record("device", display(identity));
        }
        match self.state {
            State::Ready => {}
            State::PendingReply => return Err(SpeculosError::PendingReply.into()),
            State::Broken => return Err(SpeculosError::Broken.into()),
        }

        let apdu = command.as_bytes();
        let mut frame = Vec::with_capacity(4 + apdu.len());
        frame.extend_from_slice(&(apdu.len() as u32).to_be_bytes());
        frame.extend_from_slice(apdu);
        // A partial write cannot be recovered from.
        if let Err(e) = self.stream.write_all(&frame).await {
            self.state = State::Broken;
            return Err(SpeculosError::from(e).into());
        }

        let reply = self.read_frame().await?;
        ApduAnswer::from_answer(reply)?.into_result()
    }
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/speculos/transport.rs"]
mod ai_tests;
