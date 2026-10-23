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
    PendingReply,
    /// The stream is in an unknown state.
    Broken,
}

/// A transport to a Speculos emulator's APDU socket.
///
/// Speculos frames each APDU as a 4-byte big-endian length and the bytes.
/// Replies carry the length of their data, excluding the status word, then the
/// data, then the status word.
///
/// # Timeouts
///
/// When an exchange times out, or its future is dropped, after the command was
/// sent, the reply is still coming: Speculos delivers it once the prompt on
/// screen is resolved. The transport refuses further exchanges with
/// [`SpeculosError::PendingReply`] until that reply is consumed. Speculos sends
/// the reply to whichever client is connected, so reconnecting while a prompt
/// is pending is unsafe: the new connection would read the stale reply as the
/// answer to its own command. To recover, resolve the prompt on screen, then
/// call [`discard_pending`](Self::discard_pending).
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

    /// Consume and drop the reply to a command whose exchange timed out or was
    /// cancelled.
    ///
    /// The reply to such a command is still coming, and Speculos sends it
    /// to whichever client is connected, so reconnecting while a prompt is
    /// pending is unsafe. Resolve the prompt on screen, then call this to
    /// discard the stale reply and make the transport usable again.
    ///
    /// Returns immediately if no reply is pending. Fails with
    /// [`SpeculosError::NoReply`] if the reply does not arrive within
    /// `timeout`, leaving it pending, and with [`SpeculosError::Broken`] if the
    /// connection is broken. If the reply cannot be read, returns that error
    /// and the connection is broken.
    pub async fn discard_pending(&mut self, timeout: Duration) -> Result<(), SpeculosError> {
        match self.state {
            State::Ready => Ok(()),
            State::Broken => Err(SpeculosError::Broken),
            State::PendingReply => tokio::time::timeout(timeout, self.read_frame())
                .await
                .map_err(|_| SpeculosError::NoReply(timeout))?
                .map(drop),
        }
    }

    /// Read one reply frame, keeping partial frames in `inbox`. Cancel-safe:
    /// dropping the future loses no bytes. Sets the state to `Ready` once a
    /// frame is read, and to `Broken` on failure.
    async fn read_frame(&mut self) -> Result<ApduBuffer, SpeculosError> {
        loop {
            if let Some(header) = self.inbox.first_chunk::<4>() {
                let total = (u32::from_be_bytes(*header) as usize).saturating_add(2);
                if total > ApduBuffer::CAPACITY {
                    self.state = State::Broken;
                    return Err(SpeculosError::ResponseTooLong(total));
                }
                if self.inbox.len() >= 4 + total {
                    let mut buf = ApduBuffer::new();
                    buf.extend_from_slice(&self.inbox[4..4 + total])
                        .expect("length was checked against the capacity");
                    self.inbox.drain(..4 + total);
                    self.state = State::Ready;
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
        timeout: Option<Duration>,
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
        // A partial write cannot be recovered from, so the stream is broken
        // until the write completes, even if this future is dropped.
        self.state = State::Broken;
        self.stream
            .write_all(&frame)
            .await
            .map_err(SpeculosError::from)?;

        // The reply is owed from here on, even if this future is dropped.
        self.state = State::PendingReply;
        let reply = match timeout {
            Some(t) => tokio::time::timeout(t, self.read_frame())
                .await
                .map_err(|_| LedgerError::Timeout(t))??,
            None => self.read_frame().await?,
        };
        ApduAnswer::from_answer(reply)?.into_result()
    }
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/speculos/transport.rs"]
mod ai_tests;
