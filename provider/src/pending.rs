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

enum PendingTxStates<'a, P: BTCProvider> {
    Broadcasting(ProviderFut<'a, TXID, P>),
    WaitingMoreConfs(ProviderFut<'a, Option<usize>, P>),
    // Future has completed, and should panic if polled again
    Completed,
}

/// A Pending transaction. Periodically polls the API
#[pin_project]
pub struct PendingTx<'a, P: BTCProvider> {
    txid: TXID,
    confirmations: usize,
    state: PendingTxStates<'a, P>,
    interval: Box<dyn Stream<Item = ()> + Send + Unpin>,
    provider: &'a P,
}

impl<'a, P: BTCProvider> PendingTx<'a, P> {
    /// Creates a new outspend poller
    pub fn new(tx: BitcoinTx, provider: &'a P) -> Self {
        let txid = tx.txid();
        let fut = Box::pin(provider.broadcast(tx));
        Self {
            txid,
            confirmations: 0,
            state: PendingTxStates::Broadcasting(fut),
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

impl<'a, P: BTCProvider> Future for PendingTx<'a, P> {
    type Output = TXID;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            PendingTxStates::Broadcasting(fut) => {
                if futures_util::ready!(fut.as_mut().poll(ctx)).is_ok() {
                    let fut = Box::pin(this.provider.get_confs(*this.txid));
                    *this.state = PendingTxStates::WaitingMoreConfs(fut);
                }
            }
            PendingTxStates::WaitingMoreConfs(fut) => {
                let _ready = futures_util::ready!(this.interval.poll_next_unpin(ctx));

                if let Ok(Some(confs)) = futures_util::ready!(fut.as_mut().poll(ctx)) {
                    // If we have enough confs, ready now
                    if confs >= *this.confirmations {
                        *this.state = PendingTxStates::Completed;
                        return Poll::Ready(*this.txid);
                    }
                }
                // If we want more confs, repeat
                let fut = Box::pin(this.provider.get_confs(*this.txid));
                *this.state = PendingTxStates::WaitingMoreConfs(fut)
            },
            PendingTxStates::Completed => {
                panic!("polled pending transaction future after completion")
            }
        }
        Poll::Pending
    }
}
