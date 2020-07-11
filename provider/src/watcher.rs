use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use pin_project::pin_project;

use rmn_btc::prelude::*;

use crate::{
    provider::BTCProvider,
    utils::{new_interval, StreamLast},
    ProviderFut, DEFAULT_POLL_INTERVAL,
};

enum WatcherStates<'a> {
    // Waiting for a tx to spend
    WaitingSpends(ProviderFut<'a, Option<TXID>>),
    Paused(usize, TXID),
    // Tx known, getting confs
    WaitingMoreConfs(usize, TXID, ProviderFut<'a, Option<usize>>),
    // Future has completed, and should panic if polled again
    Completed,
}

/// A stream that monitors a UTXO by its outpoint. Periodically polls the API to see if the UTXO
/// has been spent.
///
/// This struct implements `futures::stream::Stream`.
///
/// When used as a `Stream`, the stream will produce a value when a tx has been broadcast, and
/// each time the poller sees the number of confirmations increase. After receiving
/// `>= self.confirmations` confirmations, the stream will finish.
///
/// To get a future yielding a single event when the stream ends, use `StreamLast::last()`
#[pin_project(project = PollingWatcherProj)]
#[must_use = "streams do nothing unless polled"]
pub struct PollingWatcher<'a> {
    outpoint: BitcoinOutpoint,
    confirmations: usize,
    state: WatcherStates<'a>,
    interval: Box<dyn Stream<Item = ()> + Send + Unpin>,
    provider: &'a dyn BTCProvider,
}

impl<'a> PollingWatcher<'a> {
    /// Creates a new outspend poller
    pub fn new(outpoint: BitcoinOutpoint, provider: &'a dyn BTCProvider) -> Self {
        let fut = Box::pin(provider.get_outspend(outpoint));
        Self {
            outpoint,
            confirmations: 0,
            state: WatcherStates::WaitingSpends(fut),
            interval: Box::new(new_interval(DEFAULT_POLL_INTERVAL)),
            provider,
        }
    }

    /// Sets the number of confirmations before being notified of the spend
    pub fn confirmations(mut self, confs: usize) -> Self {
        self.confirmations = confs;
        self
    }

    /// Sets the polling interval
    pub fn interval<T: Into<Duration>>(mut self, duration: T) -> Self {
        self.interval = Box::new(new_interval(duration.into()));
        self
    }
}

impl StreamLast for PollingWatcher<'_> {}

impl<'a> futures_core::stream::Stream for PollingWatcher<'a> {
    type Item = (usize, Option<TXID>);

    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let PollingWatcherProj {
            outpoint,
            confirmations,
            state,
            interval,
            provider,
        } = self.project();

        match state {
            WatcherStates::WaitingSpends(fut) => {
                if let Poll::Ready(Ok(Some(txid))) = fut.as_mut().poll(ctx) {
                    if *confirmations > 0 {
                        // if we need >0 confs start waiting for more
                        let fut = Box::pin(provider.get_confs(txid));
                        *state = WatcherStates::WaitingMoreConfs(0, txid, fut);
                        return Poll::Ready(Some((0, Some(txid))));
                    } else {
                        // if 0 confs, end the stream on the first seen tx
                        *state = WatcherStates::Completed;
                        ctx.waker().wake_by_ref();
                        return Poll::Ready(Some((0, Some(txid))));
                    }
                } else {
                    // Continue otherwise
                    let fut = unpause!(ctx, interval, provider.get_outspend(*outpoint));
                    *state = WatcherStates::WaitingSpends(fut);
                }
            }
            WatcherStates::Paused(previous_confs, txid) => {
                let fut = unpause!(ctx, interval, provider.get_confs(*txid));
                *state = WatcherStates::WaitingMoreConfs(*previous_confs, *txid, fut);
            }
            WatcherStates::WaitingMoreConfs(previous_confs, txid, fut) => {
                match futures_util::ready!(fut.as_mut().poll(ctx)) {
                    // Spend tx has dropped from the mempool. Go back to `WaitingSpends`
                    Ok(None) => {
                        let fut = Box::pin(provider.get_outspend(*outpoint));
                        *state = WatcherStates::WaitingSpends(fut);
                        return Poll::Ready(Some((0, None)));
                    }
                    // Spend tx has confs. Check if there are any new ones
                    Ok(Some(confs)) => {
                        // If we're not at our limit, pause for the interval
                        if confs > *previous_confs && confs < *confirmations {
                            let t = *txid;
                            *state = WatcherStates::Paused(confs, t);
                            return Poll::Ready(Some((confs, Some(t))));
                        }

                        // If we have enough confs, go to completed
                        if confs >= *confirmations {
                            let t = *txid;
                            *state = WatcherStates::Completed;
                            ctx.waker().wake_by_ref();
                            return Poll::Ready(Some((confs, Some(t))));
                        }
                    }
                    Err(e) => {
                        if e.should_retry() {
                            *state = WatcherStates::Paused(*previous_confs, *txid);
                            return Poll::Pending;
                        }
                        // TODO: handle better?
                        panic!(
                            "Non-network error in pending tx polling. This shouldn't be reachable"
                        );
                    }
                }
            }
            WatcherStates::Completed => {
                return Poll::Ready(None);
            }
        };
        Poll::Pending
    }
}
