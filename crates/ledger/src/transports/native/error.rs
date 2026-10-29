use thiserror::Error;

use crate::common::ApduBuffer;

/// Errors from the native HID transport.
#[derive(Error, Debug)]
pub enum NativeTransportError {
    /// The device announced a response longer than an [`ApduBuffer`] holds.
    #[error(
        "Ledger device response too long: {0} bytes, max {max}. Hint: This may indicate an incompatible device.",
        max = ApduBuffer::CAPACITY
    )]
    ResponseTooLong(usize),

    /// Device not found error
    #[error("Ledger device not found")]
    DeviceNotFound,

    /// Device open error.
    #[error(
        "Error opening device. {0}. Hint: This usually means that the device is already in use by another transport instance."
    )]
    CantOpen(hidapi::HidError),

    /// SequenceMismatch
    #[error("Sequence mismatch. Got {got} from device. Expected {expected}")]
    SequenceMismatch {
        /// The sequence returned by the device
        got: u16,
        /// The expected sequence
        expected: u16,
    },

    /// A report was for another channel. Another client is probably using
    /// the device.
    #[error(
        "Report for channel {got:#06x}, expected {expected:#06x}. Hint: Is another process using the device?"
    )]
    UnexpectedChannel {
        /// The channel in the report
        got: u16,
        /// The channel this transport uses
        expected: u16,
    },

    /// A report carried an unexpected tag byte.
    #[error("Unexpected report tag {0:#04x}")]
    UnexpectedTag(u8),

    /// A report was shorter than its header. Carries the bytes read.
    #[error("Truncated report: {0} bytes")]
    TruncatedReport(usize),

    /// A continuation report carried no payload.
    #[error("Empty continuation report")]
    EmptyReport,

    /// A write sent fewer bytes than a report.
    #[error("Short write: {written} of {expected} bytes")]
    ShortWrite {
        /// Bytes the device accepted
        written: usize,
        /// Bytes in a report
        expected: usize,
    },

    /// The thread that runs hidapi context calls has stopped.
    #[error("The HID context thread is unavailable")]
    HidThreadUnavailable,

    /// The thread that drives the device has stopped.
    #[error("The device I/O thread is unavailable")]
    IoThreadUnavailable,

    /// HID error
    #[error(transparent)]
    Hid(#[from] hidapi::HidError),

    /// Termux USB FD env var does not exist or fails to parse. This error is
    /// only returned by android-specific code paths, and may be safely ignored
    /// by non-android users
    #[error("Invalid TERMUX_USB_FD variable. Are you using termux-usb?")]
    InvalidTermuxUsbFd,
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/native/error.rs"]
mod ai_tests;
