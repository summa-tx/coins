use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use pin_project::pin_project;
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;

use rmn_btc::prelude::*;

use crate::{DEFAULT_POLL_INTERVAL, interval, provider::BTCProvider};

type ProviderFut<'a, T, P> = Pin<Box<dyn Future<Output = Result<T, <P as BTCProvider>::Error>> + 'a + Send>>;

enum WatcherStates<'a, P: BTCProvider> {
    // Waiting for a tx to spend
    WaitingSpends(ProviderFut<'a, Option<TXID>, P>),
    // Tx known, getting confs
    WaitingMoreConfs(TXID, ProviderFut<'a, Option<usize>, P>),
    // Future has completed, and should panic if polled again
    Completed,
}

/// Polls the API for the tx that spends an outpoint
#[pin_project]
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

impl<'a, P: BTCProvider> Future for PollingWatcher<'a, P> {
    type Output = TXID;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            WatcherStates::WaitingSpends(fut) => {
                let _ready = futures_util::ready!(this.interval.poll_next_unpin(ctx));

                if let Ok(Some(txid)) = futures_util::ready!(fut.as_mut().poll(ctx)) {
                    // If a tx has been found, and we want 0 confs, ready now.
                    if *this.confirmations == 0 {
                        *this.state = WatcherStates::Completed;
                        return Poll::Ready(txid)
                    }
                    // If we want >0 confs, go to getting confs
                    let fut = Box::pin(this.provider.get_confs(txid));
                    *this.state = WatcherStates::WaitingMoreConfs(txid, fut)
                } else {
                    // Continue otherwise
                    let fut = Box::pin(this.provider.get_outspend(*this.outpoint));
                    *this.state = WatcherStates::WaitingSpends(fut)
                }
            },
            WatcherStates::WaitingMoreConfs(txid, fut) => {
                let _ready = futures_util::ready!(this.interval.poll_next_unpin(ctx));

                if let Ok(Some(confs)) = futures_util::ready!(fut.as_mut().poll(ctx)) {
                    // If we have enough confs, ready now
                    if confs >= *this.confirmations {
                        let txid = *txid;
                        *this.state = WatcherStates::Completed;
                        return Poll::Ready(txid)
                    }
                }
                // If we want more confs, repeat
                let fut = Box::pin(this.provider.get_confs(*txid));
                *this.state = WatcherStates::WaitingMoreConfs(*txid, fut)
            },
            WatcherStates::Completed => {
                panic!("polled pending transaction future after completion")
            }
        }

        Poll::Pending
    }
}
