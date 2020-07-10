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
    utils::{interval, StreamLast},
    ProviderFut, DEFAULT_POLL_INTERVAL,
};

enum WatcherStates<'a, P: BTCProvider> {
    // Waiting for a tx to spend
    WaitingSpends(ProviderFut<'a, Option<TXID>, P>),
    Paused(usize, TXID),
    // Tx known, getting confs
    WaitingMoreConfs(usize, TXID, ProviderFut<'a, Option<usize>, P>),
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
pub struct PollingWatcher<'a, P: BTCProvider> {
    outpoint: BitcoinOutpoint,
    confirmations: usize,
    state: WatcherStates<'a, P>,
    interval: Box<dyn Stream<Item = ()> + Send + Unpin>,
    provider: &'a P,
}

impl<'a, P: BTCProvider> PollingWatcher<'a, P> {
    /// Creates a new outspend poller
    pub fn new(outpoint: BitcoinOutpoint, provider: &'a P) -> Self {
        let fut = Box::pin(provider.get_outspend(outpoint));
        Self {
            outpoint,
            confirmations: 0,
            state: WatcherStates::WaitingSpends(fut),
            interval: Box::new(interval(DEFAULT_POLL_INTERVAL)),
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
        self.interval = Box::new(interval(duration.into()));
        self
    }
}

impl<P: BTCProvider> StreamLast for PollingWatcher<'_, P> {}

impl<'a, P: BTCProvider> futures_core::stream::Stream for PollingWatcher<'a, P> {
    type Item = (usize, TXID);

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
                        let fut = Box::pin(provider.get_confs(txid));
                        *state = WatcherStates::WaitingMoreConfs(0, txid, fut);
                        return Poll::Ready(Some((0, txid)));
                    } else {
                        *state = WatcherStates::Completed;
                        ctx.waker().wake_by_ref();
                        return Poll::Ready(Some((0, txid)));
                    }
                } else {
                    // Continue otherwise
                    let _ready = futures_util::ready!(interval.poll_next_unpin(ctx));
                    let fut = Box::pin(provider.get_outspend(*outpoint));
                    *state = WatcherStates::WaitingSpends(fut);
                }
            }
            WatcherStates::Paused(previous_confs, txid) => {
                let _ready = futures_util::ready!(interval.poll_next_unpin(ctx));
                let fut = Box::pin(provider.get_confs(*txid));
                *state = WatcherStates::WaitingMoreConfs(*previous_confs, *txid, fut);
                ctx.waker().wake_by_ref();
            }
            WatcherStates::WaitingMoreConfs(previous_confs, txid, fut) => {
                if let Ok(Some(confs)) = futures_util::ready!(fut.as_mut().poll(ctx)) {
                    // If we're not at our limit
                    if confs > *previous_confs && confs < *confirmations {
                        let t = *txid;
                        *state = WatcherStates::Paused(confs, t);
                        return Poll::Ready(Some((confs, t)));
                    }

                    // If we have enough confs, ready now
                    if confs >= *confirmations {
                        let t = *txid;
                        *state = WatcherStates::Completed;
                        ctx.waker().wake_by_ref();
                        return Poll::Ready(Some((confs, t)));
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
