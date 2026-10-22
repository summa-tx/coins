//! APDU transport for the Speculos Ledger emulator.
//!
//! [`SpeculosTransport`] speaks Speculos's raw TCP APDU protocol.

mod error;
pub use error::SpeculosError;

mod transport;
pub use transport::SpeculosTransport;
