use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use pin_project::pin_project;

use rmn_btc::prelude::*;

use crate::{provider::BTCProvider, utils::interval, ProviderFut, DEFAULT_POLL_INTERVAL};

/// Polls the API for the chain tip. Updates every time the tip changes
#[pin_project(project = TipsProj)]
#[must_use = "streams do nothing unless polled"]
pub struct Tips<'a, P: BTCProvider> {
    limit: usize,
    interval: Box<dyn Stream<Item = ()> + Send + Unpin>,
    provider: &'a P,
    fut_opt: Option<ProviderFut<'a, BlockHash, P>>,
    last: Option<BlockHash>,
}

impl<'a, P: BTCProvider> Tips<'a, P> {
    /// Instantiate a new Tips. Return at most `limit` new chaintips.
    pub fn new(limit: usize, provider: &'a P) -> Self {
        let fut = Box::pin(provider.tip_hash());
        Self {
            limit,
            interval: Box::new(interval(DEFAULT_POLL_INTERVAL)),
            provider,
            fut_opt: Some(fut),
            last: None,
        }
    }

    /// Sets the polling interval
    pub fn interval<T: Into<Duration>>(mut self, duration: T) -> Self {
        self.interval = Box::new(interval(duration.into()));
        self
    }
}

impl<'a, P: BTCProvider> futures::stream::Stream for Tips<'a, P> {
    type Item = BlockHash;

    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let TipsProj {
            limit,
            interval,
            provider,
            fut_opt,
            last,
        } = self.project();

        // if our limit has run down, end the stream
        if *limit == 0 {
            return Poll::Ready(None);
        }

        if let Some(fut) = fut_opt {
            let result = futures_util::ready!(fut.as_mut().poll(ctx));
            *fut_opt = None;

            // Errors will fail through to being retried at the interval
            if let Ok(block_hash) = result {
                // if we just saw it, don't emit again
                if let Some(hash) = *last {
                    if hash == block_hash {
                        return Poll::Pending;
                    }
                }
                // if it has changed, or this is the first, emit it
                *last = Some(block_hash);
                *limit -= 1;
                return Poll::Ready(Some(block_hash));
            }
        }

        // if the interval has elapsed, reset the fut
        let _ready = futures_util::ready!(interval.poll_next_unpin(ctx));
        *fut_opt = Some(Box::pin(provider.tip_hash()));
        Poll::Pending
    }
}
