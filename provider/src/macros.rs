// Used to unpause things blocked by an interval. Uses `ready!` to shortcut to Pending
// if the interval has not yet elapsed
macro_rules! unpause {
    ($ctx:expr, $interval:expr, $next_fut:expr) => {
        {
            let _ready = futures_util::ready!($interval.poll_next_unpin($ctx));
            $ctx.waker().wake_by_ref();
            Box::pin($next_fut)
        }
    }
}
