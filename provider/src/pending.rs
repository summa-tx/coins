use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use pin_project::pin_project;

use rmn_btc::prelude::*;

use crate::{provider::BTCProvider, DEFAULT_POLL_INTERVAL, utils::{StreamLast, interval}};

type ProviderFut<'a, T, P> =
    Pin<Box<dyn Future<Output = Result<T, <P as BTCProvider>::Error>> + 'a + Send>>;

enum PendingTxStates<'a, P: BTCProvider> {
    Broadcasting(ProviderFut<'a, TXID, P>),
    WaitingMoreConfs(usize, ProviderFut<'a, Option<usize>, P>),
    // Future has completed, and should panic if polled again
    Completed,
}

/// A Pending transaction. Periodically polls the API to see if it has been confirmed.
///
/// This struct implements both `std::future::Future` and `futures::stream::Stream`.
///
/// When `await`ed as a future, the future will resolve to the TXID as soon as the poller sees it
/// receive `>= self.confirmations` confirmations.
///
/// When used as a `Stream`, the stream will produce a value when the tx has been broadcast, and
/// each time the poller sees the number of confirmations increase. After receiving
/// `>= self.confirmations` confirmations, the stream will finish.
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

impl<P: BTCProvider> StreamLast for PendingTx<'_, P> {}

impl<'a, P: BTCProvider> futures::stream::Stream for PendingTx<'a, P> {
    type Item = (usize, TXID);

    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.state {
            PendingTxStates::Broadcasting(fut) => {
                if futures_util::ready!(fut.as_mut().poll(ctx)).is_ok() {
                    let fut = Box::pin(this.provider.get_confs(*this.txid));
                    *this.state = PendingTxStates::WaitingMoreConfs(0, fut);
                    return Poll::Ready(Some((0, *this.txid)));
                }
            },
            PendingTxStates::WaitingMoreConfs(previous_confs, fut) => {
                let _ready = futures_util::ready!(this.interval.poll_next_unpin(ctx));

                if let Ok(Some(confs)) = futures_util::ready!(fut.as_mut().poll(ctx)) {
                    // If we're not at our limit
                    if confs > *previous_confs && confs < *this.confirmations {
                        let fut = Box::pin(this.provider.get_confs(*this.txid));
                        *this.state = PendingTxStates::WaitingMoreConfs(confs, fut);
                        return Poll::Ready(Some((confs, *this.txid)));
                    }

                    // If we have enough confs, ready now
                    if confs >= *this.confirmations {
                        *this.state = PendingTxStates::Completed;
                        ctx.waker().wake_by_ref();
                        return Poll::Ready(Some((confs, *this.txid)));
                    }
                }
                // If we want more confs, repeat
                let fut = Box::pin(this.provider.get_confs(*this.txid));
                *this.state = PendingTxStates::WaitingMoreConfs(*previous_confs, fut);
            },
            PendingTxStates::Completed => {
                return Poll::Ready(None);
            }
        }
        Poll::Pending
    }
}
