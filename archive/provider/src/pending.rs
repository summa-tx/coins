use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use pin_project::pin_project;

use bitcoins::prelude::*;

use crate::{
    provider::BtcProvider,
    utils::{new_interval, StreamLast},
    ProviderFut, DEFAULT_POLL_INTERVAL,
};

enum PendingTxStates<'a> {
    Broadcasting(ProviderFut<'a, TXID>),
    Paused,
    WaitingConfFut(ProviderFut<'a, Option<usize>>),
    // Stream has failed and should not be polled again
    Dropped,
    // Stream has completed, and should not be polled again
    Completed,
}

/// A pending transaction. Periodically polls the API to see if it has been confirmed.
///
/// If the transaction is confirmed, the stream will yield the number of confirmations it has
/// received. 0 confirmations indicates a tx in the mempool, but not yet confirmed. Due to API
/// limitations, if the transaction receives a confirmation before the first poll, 0 confirmations
/// will be reported.
///
/// This struct implements `futures::stream::Stream`.
///
/// When used as a `Stream`, the stream will produce a value when the tx has been broadcast, and
/// each time the poller sees the number of confirmations increase. After receiving
/// `>= self.confs_wanted` confirmations, the stream will finish.
///
/// To get a future yielding a single event when the stream ends, use `StreamLast::last()`
#[pin_project(project = PendingTxProj)]
#[must_use = "streams do nothing unless polled"]
pub struct PendingTx<'a> {
    txid: TXID,
    tx: BitcoinTx,
    confs_wanted: usize,
    confs_have: usize,
    state: PendingTxStates<'a>,
    interval: Box<dyn Stream<Item = ()> + Send + Unpin>,
    provider: &'a dyn BtcProvider,
}

impl<'a> PendingTx<'a> {
    /// Creates a new outspend poller
    pub fn new(tx: BitcoinTx, provider: &'a dyn BtcProvider) -> Self {
        let txid = tx.txid();
        let fut = Box::pin(provider.broadcast(tx.clone()));
        Self {
            txid,
            tx,
            confs_wanted: 0,
            confs_have: 0,
            state: PendingTxStates::Broadcasting(fut),
            interval: Box::new(new_interval(DEFAULT_POLL_INTERVAL)),
            provider,
        }
    }

    /// Sets the number of confs_wanted before being notified of the spend
    pub fn confirmations(mut self, confs: usize) -> Self {
        self.confs_wanted = confs;
        self
    }

    /// Sets the polling interval
    pub fn interval<T: Into<Duration>>(mut self, duration: T) -> Self {
        self.interval = Box::new(new_interval(duration.into()));
        self
    }
}

impl StreamLast for PendingTx<'_> {}

impl<'a> futures_core::stream::Stream for PendingTx<'a> {
    type Item = Result<(usize, TXID), BitcoinTx>;

    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let PendingTxProj {
            txid,
            tx,
            confs_wanted,
            confs_have,
            state,
            interval,
            provider,
        } = self.project();

        match state {
            PendingTxStates::Broadcasting(fut) => {
                if futures_util::ready!(fut.as_mut().poll(ctx)).is_ok() {
                    let fut = Box::pin(provider.get_confs(*txid));
                    *state = PendingTxStates::WaitingConfFut(fut);
                    ctx.waker().wake_by_ref();
                    return Poll::Ready(Some(Ok((0, *txid))));
                }
            }
            PendingTxStates::Paused => {
                let fut = unpause!(ctx, interval, provider.get_confs(*txid));
                *state = PendingTxStates::WaitingConfFut(fut);
            }
            PendingTxStates::WaitingConfFut(fut) => {
                match futures_util::ready!(fut.as_mut().poll(ctx)) {
                    Ok(Some(confs)) => {
                        *confs_have = confs;
                        // If we're not at our limit
                        if confs > *confs_have && confs < *confs_wanted {
                            *state = PendingTxStates::Paused;
                            return Poll::Ready(Some(Ok((confs, *txid))));
                        }

                        // If we have enough confs, ready now
                        if confs >= *confs_wanted {
                            *state = PendingTxStates::Completed;
                            ctx.waker().wake_by_ref();
                            return Poll::Ready(Some(Ok((confs, *txid))));
                        }

                        *state = PendingTxStates::Paused;
                    }
                    Ok(None) => {
                        *state = PendingTxStates::Dropped;
                        ctx.waker().wake_by_ref();
                        return Poll::Ready(Some(Err(tx.clone())));
                    }
                    Err(e) => {
                        if !e.from_parsing() {
                            *state = PendingTxStates::Paused;
                            return Poll::Pending;
                        }
                        // TODO: handle better?
                        panic!(
                            "Non-network error in pending tx polling. This shouldn't be reachable"
                        );
                    }
                }
            }
            PendingTxStates::Dropped => {
                return Poll::Ready(None);
            }
            PendingTxStates::Completed => {
                return Poll::Ready(None);
            }
        }
        Poll::Pending
    }
}
