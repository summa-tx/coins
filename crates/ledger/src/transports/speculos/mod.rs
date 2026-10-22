//! Transport and control client for the Speculos Ledger emulator.
//!
//! Speculos runs Ledger app binaries on a host machine, and exposes two ports:
//!
//! - the APDU port (default 9999), a raw TCP socket. [`SpeculosTransport`]
//!   speaks it and implements [`LedgerTransport`](crate::transports::LedgerTransport).
//! - the HTTP API (default 5000), which presses buttons, reads the screen
//!   events and takes screenshots. [`SpeculosClient`] drives it.
//!
//! Commands that need on-device approval block until the prompt is resolved,
//! so the exchange and the approval must run concurrently:
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use coins_ledger::{
//!     CommandBuilder, Model,
//!     transports::{
//!         LedgerTransport,
//!         speculos::{Action, Button, SpeculosClient, SpeculosError, SpeculosTransport},
//!     },
//! };
//!
//! let mut ledger = SpeculosTransport::connect("127.0.0.1:9999", Model::NanoSPlus).await?;
//! let client = SpeculosClient::new("http://127.0.0.1:5000")?;
//! let cmd = CommandBuilder::new().cla(0xe0).ins(0x02).build()?;
//!
//! // Match only events from this step.
//! client.clear_events().await?;
//! let (answer, approved) = tokio::join!(ledger.exchange(cmd, None), async {
//!     client.wait_for_text("Approve", Duration::from_secs(10)).await?;
//!     client.button(Button::Both, Action::PressAndRelease { delay: None }).await?;
//!     Ok::<_, SpeculosError>(())
//! });
//! approved?;
//! let answer = answer?;
//! # Ok(()) }
//! ```

mod error;
pub use error::SpeculosError;

mod transport;
pub use transport::SpeculosTransport;

mod client;
pub use client::{Action, Button, ScreenEvent, SpeculosClient};

#[cfg(test)]
#[path = "../../../ai-tests/transports/speculos/mod.rs"]
mod ai_tests;
