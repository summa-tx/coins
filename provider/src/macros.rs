// Used to unpause things blocked by an interval. Uses `ready!` to shortcut to Pending
// if the interval has not yet elapsed
macro_rules! unpause {
    ($ctx:expr, $interval:expr, $next_fut:expr) => {{
        let _ready = futures_util::ready!($interval.poll_next_unpin($ctx));
        $ctx.waker().wake_by_ref();
        Box::pin($next_fut)
    }};
}

/// Used to make shortcutting to None responses easier.
/// Bitcoin node APIs use the ERR_NOT_FOUND code to indicate that a block or header is not present
macro_rules! rpc_if_found {
    ($func:expr) => {{
        let result = $func.map_err(Into::<crate::provider::ProviderError>::into);
        if let Err(e) = result {
            if let ProviderError::RPCErrorResponse(resp) = &e {
                if resp.code == crate::rpc::ERR_NOT_FOUND {
                    // RPC not found code
                    return Ok(None);
                }
            }
            return Err(e);
        }
        result.unwrap()
    }};
}

// Used to make shortcutting to none responses easier.
// It's common for Bitcoin APIs to return a string instead of JSON when a TX is unknown
// The string is unparsable as JSON, so generates an error.
macro_rules! esplora_if_found {
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
