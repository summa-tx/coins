//! AI-written tests for `NativeTransportError`. A submodule of
//! `src/transports/native/error.rs`.

use super::*;

#[test]
fn timeout_names_the_duration() {
    let msg = NativeTransportError::Timeout(Duration::from_millis(1500)).to_string();
    assert!(msg.contains("1.5s"), "{msg}");
}

#[test]
fn response_too_long_names_both_lengths() {
    let msg = NativeTransportError::ResponseTooLong(300).to_string();
    assert!(msg.contains("300 bytes"), "{msg}");
    assert!(
        msg.contains(&format!("max {}", ApduBuffer::CAPACITY)),
        "{msg}"
    );
}
