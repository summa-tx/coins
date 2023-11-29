//! Native HID APDU transport for Ledger Nano hardware wallets

use crate::{
    common::{APDUAnswer, APDUCommand},
    errors::LedgerError,
};

use byteorder::{BigEndian, ReadBytesExt};
use hidapi_rusb::{DeviceInfo, HidApi, HidDevice};
use once_cell::sync::Lazy;
use std::{io::Cursor, sync::Mutex};

use super::NativeTransportError;

const LEDGER_VID: u16 = 0x2c97;
#[cfg(not(target_os = "linux"))]
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;
const LEDGER_CHANNEL: u16 = 0x0101;
// for Windows compatability, we prepend the buffer with a 0x00
// so the actual buffer is 64 bytes
const LEDGER_PACKET_WRITE_SIZE: u8 = 65;
const LEDGER_PACKET_READ_SIZE: u8 = 64;
const LEDGER_TIMEOUT: i32 = 10_000_000;

/// The HID API instance.
pub static HIDAPI: Lazy<HidApi> =
    Lazy::new(|| HidApi::new().expect("Failed to initialize HID API"));

/// Native HID transport for Ledger Nano hardware wallets
pub struct TransportNativeHID {
    device: Mutex<HidDevice>,
}

impl std::fmt::Debug for TransportNativeHID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportNativeHID").finish()
    }
}

#[cfg(not(target_os = "linux"))]
fn is_ledger(dev: &DeviceInfo) -> bool {
    dev.vendor_id() == LEDGER_VID && dev.usage_page() == LEDGER_USAGE_PAGE
}

#[cfg(target_os = "linux")]
fn is_ledger(dev: &DeviceInfo) -> bool {
    dev.vendor_id() == LEDGER_VID
}

/// Get a list of ledger devices available
fn list_ledgers(api: &HidApi) -> impl Iterator<Item = &DeviceInfo> {
    api.device_list().filter(|dev| is_ledger(dev))
}

#[tracing::instrument(skip_all, err)]
fn first_ledger(api: &HidApi) -> Result<HidDevice, NativeTransportError> {
    let device = list_ledgers(api)
        .next()
        .ok_or(NativeTransportError::DeviceNotFound)?;

    open_device(api, device)
}

/// Read the 5-byte response header.
fn read_response_header(rdr: &mut Cursor<&[u8]>) -> Result<(u16, u8, u16), NativeTransportError> {
    let rcv_channel = rdr.read_u16::<BigEndian>()?;
    let rcv_tag = rdr.read_u8()?;
    let rcv_seq_idx = rdr.read_u16::<BigEndian>()?;
    Ok((rcv_channel, rcv_tag, rcv_seq_idx))
}

/// Open a specific ledger device
///
/// # Note
/// No checks are made to ensure the device is a ledger device
///
/// # Warning
/// Opening the same device concurrently will lead to device lock after the first handle is closed
/// see [issue](https://github.com/ruabmbua/hidapi-rs/issues/81)
fn open_device(api: &HidApi, device: &DeviceInfo) -> Result<HidDevice, NativeTransportError> {
    let device = device
        .open_device(api)
        .map_err(NativeTransportError::CantOpen)?;
    let _ = device.set_blocking_mode(true);

    Ok(device)
}

impl TransportNativeHID {
    /// Instantiate from a device.
    fn from_device(device: HidDevice) -> Self {
        Self {
            device: Mutex::new(device),
        }
    }

    /// Get manufacturer string. Returns None on error, or on no string.
    pub fn get_manufacturer_string(&self) -> Option<String> {
        let device = self.device.lock().unwrap();
        device.get_manufacturer_string().unwrap_or_default()
    }

    /// Open all ledger devices.
    pub fn open_all_devices() -> Result<Vec<Self>, NativeTransportError> {
        let api = &HIDAPI;
        let devices = list_ledgers(api)
            .map(|dev| open_device(api, dev))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(devices.into_iter().map(Self::from_device).collect())
    }

    /// Create a new HID transport, connecting to the first ledger found
    ///
    /// # Warning
    /// Opening the same device concurrently will lead to device lock after the first handle is closed
    /// see [issue](https://github.com/ruabmbua/hidapi-rs/issues/81)
    pub fn new() -> Result<Self, NativeTransportError> {
        let api = &HIDAPI;

        #[cfg(target_os = "android")]
        {
            // Using runtime detection since it's impossible to statically target Termux.
            let is_termux = match std::env::var("PREFIX") {
                Ok(prefix_var) => prefix_var.contains("/com.termux/"),
                Err(_) => false,
            };

            if is_termux {
                // Termux uses a special environment vairable TERMUX_USB_FD for this
                let usb_fd = std::env::var("TERMUX_USB_FD")
                    .map_err(|_| NativeTransportError::InvalidTermuxUsbFd)?
                    .parse::<i32>()
                    .map_err(|_| NativeTransportError::InvalidTermuxUsbFd)?;
                api.wrap_sys_device(usb_fd, -1).map(Self::from_device)?
            } else {
                // Not sure how we should handle non-Termux Android here. This likely won't work.
                first_ledger(api).map(Self::from_device)
            }
        }

        #[cfg(not(target_os = "android"))]
        first_ledger(api).map(Self::from_device)
    }

    fn write_apdu(&self, channel: u16, apdu_command: &[u8]) -> Result<i32, NativeTransportError> {
        let device = self.device.lock().unwrap();

        let command_length = apdu_command.len();
        let mut in_data = Vec::with_capacity(command_length + 2);
        in_data.push(((command_length >> 8) & 0xFF) as u8);
        in_data.push((command_length & 0xFF) as u8);
        in_data.extend_from_slice(apdu_command);

        let mut buffer = [0u8; LEDGER_PACKET_WRITE_SIZE as usize];
        buffer[0] = ((channel >> 8) & 0xFF) as u8; // channel big endian
        buffer[1] = (channel & 0xFF) as u8; // channel big endian
        buffer[2] = 0x05u8;

        for (sequence_idx, chunk) in in_data
            .chunks((LEDGER_PACKET_WRITE_SIZE - 5) as usize)
            .enumerate()
        {
            buffer[3] = ((sequence_idx >> 8) & 0xFF) as u8; // sequence_idx big endian
            buffer[4] = (sequence_idx & 0xFF) as u8; // sequence_idx big endian
            buffer[5..5 + chunk.len()].copy_from_slice(chunk);

            let result = device.write(&buffer);

            match result {
                Ok(size) => {
                    if size < buffer.len() {
                        return Err(NativeTransportError::Comm(
                            "USB write error. Could not send whole message",
                        ));
                    }
                }
                Err(x) => return Err(NativeTransportError::Hid(x)),
            }
        }
        Ok(1)
    }

    /// Read a response APDU from the ledger channel.
    fn read_response_apdu(&self, _channel: u16) -> Result<Vec<u8>, NativeTransportError> {
        let device = self.device.lock().unwrap();

        let mut response_buffer = [0u8; LEDGER_PACKET_READ_SIZE as usize];
        let mut sequence_idx = 0u16;
        let mut expected_response_len = 0usize;
        let mut offset = 0;

        let mut answer_buf = vec![];

        loop {
            let res = device.read_timeout(&mut response_buffer, LEDGER_TIMEOUT)?;

            if (sequence_idx == 0 && res < 7) || res < 5 {
                return Err(NativeTransportError::Comm("Read error. Incomplete header"));
            }

            let mut rdr = Cursor::new(&response_buffer[..]);
            let (_, _, rcv_seq_idx) = read_response_header(&mut rdr)?;

            if rcv_seq_idx != sequence_idx {
                return Err(NativeTransportError::SequenceMismatch {
                    got: rcv_seq_idx,
                    expected: sequence_idx,
                });
            }

            // The header packet contains the number of bytes of response data
            if rcv_seq_idx == 0 {
                expected_response_len = rdr.read_u16::<BigEndian>()? as usize;
            }

            let remaining_in_buf = response_buffer.len() - rdr.position() as usize;
            let missing = expected_response_len - offset;
            let end_p = rdr.position() as usize + std::cmp::min(remaining_in_buf, missing);

            let new_chunk = &response_buffer[rdr.position() as usize..end_p];

            // Copy the response to the answer
            answer_buf.extend(new_chunk);
            // answer_buf[offset..offset + new_chunk.len()].copy_from_slice(new_chunk);
            offset += new_chunk.len();

            if offset >= expected_response_len {
                return Ok(answer_buf);
            }

            sequence_idx += 1;
        }
    }

    /// Exchange an APDU with the device. The response data will be written to `answer_buf`, and a
    /// `APDUAnswer` struct will be created with a reference to `answer_buf`.
    ///
    /// It is strongly recommended that you use the `APDUAnswer` api instead of reading the raw
    /// answer_buf response.
    ///
    /// If the method errors, the buf may contain a partially written response. It is not advised
    /// to read this.
    pub fn exchange(&self, command: &APDUCommand) -> Result<APDUAnswer, LedgerError> {
        self.write_apdu(LEDGER_CHANNEL, &command.serialize())?;

        let answer_buf = self.read_response_apdu(LEDGER_CHANNEL)?;

        let apdu_answer = APDUAnswer::from_answer(answer_buf)?;

        match apdu_answer.response_status() {
            None => Ok(apdu_answer),
            Some(response) => {
                if response.is_success() {
                    Ok(apdu_answer)
                } else {
                    Err(response.into())
                }
            }
        }
    }
}

/*******************************************************************************
*   (c) 2018-2022 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
