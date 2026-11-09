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
    #[error(
        "No Ledger device found. Hint: connect and unlock the device, and close other apps using it, such as Ledger Live. On Linux, check the udev rules."
    )]
    DeviceNotFound,

    /// Device open error.
    #[error(
        "Could not open the Ledger device: {0}. Hint: This usually means that the device is already in use by another transport instance."
    )]
    CantOpen(hidapi::HidError),

    /// SequenceMismatch
    #[error(
        "Report sequence mismatch: got {got}, expected {expected}. Hint: Is another process reading from the device?"
    )]
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
    #[error("Unexpected report tag {0:#04x}. Hint: This may indicate an incompatible device.")]
    UnexpectedTag(u8),

    /// A report was shorter than its header. Carries the bytes read.
    #[error("Truncated report: {0} bytes. Hint: This may indicate an incompatible device.")]
    TruncatedReport(usize),

    /// A continuation report carried no payload.
    #[error("Empty continuation report. Hint: This may indicate an incompatible device.")]
    EmptyReport,

    /// A write sent fewer bytes than a report.
    #[error(
        "Short write to the Ledger device: {written} of {expected} bytes. Hint: Is the device still connected?"
    )]
    ShortWrite {
        /// Bytes the device accepted
        written: usize,
        /// Bytes in a report
        expected: usize,
    },

    /// HID discovery is unavailable for the rest of the process, because
    /// hidapi failed to initialize.
    #[error(
        "HID discovery unavailable: hidapi failed to initialize. Hint: check that hidapi's system library is installed and the process can access USB devices."
    )]
    HidThreadUnavailable,

    /// The transport is closed, after an error it cannot recover from or a
    /// lost device. Reopen it.
    #[error(
        "Ledger transport closed. Hint: reopen it with `HidTransport::open` or `HidTransport::open_first`."
    )]
    IoThreadUnavailable,

    /// HID error
    #[error("HID I/O with the Ledger device failed: {0}. Hint: Is the device still connected?")]
    Hid(#[from] hidapi::HidError),

    /// `TERMUX_USB_FD` is missing or does not parse. Returned only on Android,
    /// when opening the first device under Termux.
    #[error("TERMUX_USB_FD is missing or invalid. Hint: run the program through `termux-usb -e`.")]
    InvalidTermuxUsbFd,
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/native/error.rs"]
mod ai_tests;
