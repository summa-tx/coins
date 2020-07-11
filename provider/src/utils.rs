use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;

use futures_core::Stream;
use futures_timer::Delay;
use futures_util::{
    stream::{self, StreamExt},
    FutureExt,
};
use std::time::Duration;

use rmn_btc::prelude::TXID;

// Async delay stream
pub(crate) fn new_interval(duration: Duration) -> impl Stream<Item = ()> + Send + Unpin {
    stream::unfold((), move |_| Delay::new(duration).map(|_| Some(((), ())))).map(drop)
}

/// Future for the `last` method. Resolves to the last item in the stream.
#[pin_project(project = LastProj)]
#[derive(Debug)]
#[must_use = "futures do nothing unless awaited or polled"]
pub struct Last<St, I>
where
    St: Stream<Item = I> + StreamExt,
{
    #[pin]
    stream: St,
    item: Option<I>,
}

impl<St, I> Last<St, I>
where
    St: Stream<Item = I> + StreamExt,
{
    fn new(stream: St) -> Last<St, I> {
        Self { stream, item: None }
    }
}

/// Extension trait for streams. Provides a future that resolves to the last item in the stream.
pub trait StreamLast: Sized + Stream + StreamExt {
    /// Consume this stream, return a future that resolves to the last item. This future resolves
    /// to the most recently yielded item when the stream yields `None`.
    ///
    /// If the stream is empty, this will resolve to `None`. Otherwise it will resolve to
    /// `Some(last)`.
    ///
    /// Note: this future relies on correct implementation of the `Stream` trait. If the stream
    /// never terminates (by yielding `None`), the future will never resolve.
    fn last(self) -> Last<Self, <Self as Stream>::Item> {
        Last::new(self)
    }
}

impl<St, I> Future for Last<St, I>
where
    St: Sized + Stream<Item = I> + StreamExt,
{
    type Output = Option<I>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<I>> {
        let LastProj { stream, item } = self.project();

        match futures_util::ready!(stream.poll_next(ctx)) {
            Some(i) => {
                *item = Some(i);
                Poll::Pending
            }
            None => Poll::Ready(Some(item.take().unwrap())),
        }
    }
}

/// Get a merkle proof from a block txid list.
pub fn merkle_from_txid_list(txid: TXID, block: Vec<TXID>) -> Option<Vec<TXID>> {
    // TODO
    unimplemented!()
}
