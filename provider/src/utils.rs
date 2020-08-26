use std::{
    future::Future,
    io::Write,
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

use bitcoins::prelude::TXID;
use coins_core::prelude::{Hash256, Hash256Digest, MarkedDigest, MarkedDigestOutput};

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

/// Create a full merkle tree from a txid list.
pub fn create_tree(leaves: &[TXID]) -> Vec<TXID> {
    let mut size = leaves.len();
    let mut nodes = leaves.to_vec();

    if size == 0 {
        nodes.push(TXID::default());
        nodes
    } else {
        let mut i = 0;

        while size > 1 {
            for j in (0..size).step_by(2) {
                let k = std::cmp::min(j + 1, size - 1);
                let left = nodes[i + j];
                let right = nodes[i + k];

                let mut ctx = Hash256::default();
                ctx.write_all(left.as_slice())
                    .expect("no error on heap allocation");
                ctx.write_all(right.as_slice())
                    .expect("no error on heap allocation");
                let digest: TXID = ctx.finalize_marked();
                nodes.push(digest);
            }

            i += size;
            size = (size + 1) >> 1;
        }

        nodes
    }
}

/// Create a merkle branch from an index and a txid list.
pub fn create_branch(index: usize, leaves: &[TXID]) -> Vec<Hash256Digest> {
    let mut size = leaves.len();
    let nodes = create_tree(&leaves);

    let mut idx = index;
    let mut branch: Vec<Hash256Digest> = vec![];

    let mut i = 0;
    while size > 1 {
        let j = std::cmp::min(idx ^ 1, size - 1);

        branch.push(nodes[i + j].to_internal().into());

        idx >>= 1;
        i += size;
        size = (size + 1) >> 1;
    }

    branch
}

/// Get a merkle proof from a block txid list.
pub fn merkle_from_txid_list(txid: TXID, block: &[TXID]) -> Option<(usize, Vec<Hash256Digest>)> {
    let index = block.iter().position(|t| *t == txid);

    match index {
        Some(i) => {
            let branch = create_branch(i, block);
            Some((i, branch))
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_tree() {
        let cases = [(
            vec![TXID::from([0x00; 32]), TXID::from([0x01; 32])],
            vec![
                TXID::from([0x00; 32]),
                TXID::from([0x01; 32]),
                TXID::from([
                    0x70, 0x5e, 0xde, 0x9d, 0x42, 0x47, 0x6f, 0xc3, 0xe5, 0xa9, 0x78, 0xb0, 0x42,
                    0xce, 0x79, 0x0a, 0x19, 0x36, 0x78, 0xf4, 0x6d, 0x19, 0xf4, 0x7e, 0xc4, 0xab,
                    0x46, 0x53, 0x9c, 0x47, 0xb7, 0x6d,
                ]),
            ],
        )];

        for case in cases.iter() {
            let result = create_tree(&case.0);
            assert_eq!(result, case.1);
        }
    }

    #[test]
    fn should_create_branch() {
        let cases = [(
            (
                0,
                vec![
                    TXID::from([0x00; 32]),
                    TXID::from([0x01; 32]),
                    TXID::from([0x02; 32]),
                    TXID::from([0x03; 32]),
                ],
            ),
            vec![
                TXID::from([0x01; 32]).to_internal(),
                TXID::from([
                    0x1b, 0x12, 0xc1, 0x42, 0xca, 0x6f, 0xab, 0xe6, 0xcc, 0xcf, 0x4a, 0xa5, 0x2a,
                    0xff, 0x1f, 0x21, 0x88, 0x2e, 0xc4, 0x9d, 0xa2, 0xdd, 0x4c, 0x1c, 0xf7, 0x0a,
                    0xbf, 0xfc, 0xc4, 0x5f, 0x59, 0x1b,
                ])
                .to_internal(),
            ],
        )];

        for case in cases.iter() {
            let (index, leaves) = &case.0;
            let result: Vec<_> = create_branch(*index, leaves)
                .into_iter()
                .map(|d| d.to_internal())
                .collect();
            assert_eq!(result, case.1);
        }
    }
}
