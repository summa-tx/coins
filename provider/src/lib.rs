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

pub use provider::*;

type Encoder = rmn_btc::Encoder;

use std::time::Duration;
use futures_core::Stream;
use futures_util::{stream, FutureExt, StreamExt};
use futures_timer::Delay;

// Async delay stream
pub(crate) fn interval(duration: Duration) -> impl Stream<Item = ()> + Send + Unpin {
    stream::unfold((), move |_| Delay::new(duration).map(|_| Some(((), ())))).map(drop)
}

/// The default poll interval, set to 300 seconds (5 minutes)
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(300 * 1000);
