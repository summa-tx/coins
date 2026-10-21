//! AI-written tests for `LedgerError`. A submodule of `src/errors.rs`.

use std::{error::Error, fmt, time::Duration};

use super::*;
use crate::transports::native::NativeTransportError;

#[test]
fn timeout_display_names_the_duration() {
    let msg = LedgerError::Timeout(Duration::from_millis(1500)).to_string();
    assert_eq!(msg, "Ledger device did not respond within 1.5s");
}

#[test]
fn native_errors_box_into_transport() {
    let err = LedgerError::from(NativeTransportError::DeviceNotFound);
    assert_eq!(err.to_string(), "Ledger device not found");
    let LedgerError::Transport(inner) = err else {
        panic!("expected Transport, got {err:?}");
    };
    assert!(matches!(
        inner.downcast_ref(),
        Some(NativeTransportError::DeviceNotFound)
    ));
}

/// What a transport outside this crate would report.
#[derive(Debug)]
struct WebHidError;

impl fmt::Display for WebHidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebHID: device lost")
    }
}

impl Error for WebHidError {}

#[test]
fn third_party_errors_box_into_transport() {
    // `?` from a `Box<dyn Error>` and from an explicit box both land in
    // `Transport`, and the original type is recoverable.
    let via_box: Result<(), LedgerError> = (|| {
        Err::<(), Box<dyn Error + Send + Sync>>(Box::new(WebHidError))?;
        Ok(())
    })();
    let err = via_box.unwrap_err();
    assert_eq!(err.to_string(), "WebHID: device lost");
    let LedgerError::Transport(inner) = err else {
        panic!("expected Transport, got {err:?}");
    };
    assert!(inner.downcast_ref::<WebHidError>().is_some());
}
