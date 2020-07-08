//! Pluggable standardized Bitcoin backend

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

/// Bitcoin Provider trait
pub mod provider;

/// Pending Transaction
pub mod pending;

/// Outpoint spend watcher
pub mod watcher;

/// Utils
pub mod utils;

#[cfg(feature = "esplora")]
/// EsploraProvider
pub mod esplora;

pub use provider::*;

type Encoder = rmn_btc::Encoder;

use std::time::Duration;

/// The default poll interval, set to 300 seconds (5 minutes)
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(180 * 1000);
