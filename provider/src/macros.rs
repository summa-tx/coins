// Used to unpause things blocked by an interval. Uses `ready!` to shortcut to Pending
// if the interval has not yet elapsed
macro_rules! unpause {
    ($ctx:expr, $interval:expr, $next_fut:expr) => {{
        let _ready = futures_util::ready!($interval.poll_next_unpin($ctx));
        $ctx.waker().wake_by_ref();
        Box::pin($next_fut)
    }};
}

// Used to make shortcutting to none responses easier.
// It's common for Bitcoin APIs to return a string instead of JSON when a TX is unknown
// The string is unparsable as JSON, so generates an error.
macro_rules! none_if_unparsable {
    ($func:expr) => {{
        let result = $func.map_err(Into::<crate::provider::ProviderError>::into);
        if let Err(e) = result {
            if !e.from_parsing() {
                return Err(e);
            } else {
                return Ok(None);
            }
        }
        result.unwrap()
    }};
}
