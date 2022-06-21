//! Native HID APDU transport for Ledger Nano hardware wallets
use cfg_if::cfg_if;
use lazy_static::lazy_static;
use thiserror::Error;

use crate::{
    common::{APDUAnswer, APDUCommand},
    errors::LedgerError,
};

use std::{ffi::CString, io::Cursor};

use byteorder::{BigEndian, ReadBytesExt};
use hidapi_rusb::HidDevice;
use std::cell::RefCell;
use std::sync::{Arc, Mutex, Weak};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        use nix::{ioctl_read, convert_ioctl_res, request_code_read, ioc};
        // use libc;
        use std::{ffi::CStr, mem};
    } else {
        // Mock the type in other target_os
        mod nix {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("")]
                Unimplemented,
            }
        }
    }
}

const LEDGER_VID: u16 = 0x2c97;

#[cfg(not(target_os = "linux"))]
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;
const LEDGER_CHANNEL: u16 = 0x0101;
const LEDGER_PACKET_SIZE: u8 = 64;

const LEDGER_TIMEOUT: i32 = 10_000_000;

/// Ledger transport errors
#[cfg(not(target_arch = "wasm32"))]
#[derive(Error, Debug)]
pub enum NativeTransportError {
    /// Device not found error
    #[error("Ledger device not found")]
    DeviceNotFound,
    /// SequenceMismatch
    #[error("Sequence mismatch. Got {got} from device. Expected {expected}")]
    SequenceMismatch {
        /// The sequence returned by the device
        got: u16,
        /// The expected sequence
        expected: u16,
    },
    /// Communication error
    #[error("Ledger device: communication error `{0}`")]
    Comm(&'static str),
    /// Ioctl error
    #[error(transparent)]
    Ioctl(#[from] nix::Error),
    /// i/o error
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// HID error
    #[error(transparent)]
    Hid(#[from] hidapi_rusb::HidError),
    /// UT8F error
    #[error(transparent)]
    UTF8(#[from] std::str::Utf8Error),
    #[error("Invalid TERMUX_USB_FD variable. Are you using termux-usb?")]
    InvalidTermuxUsbFd,
}

struct HidApiWrapper {
    _api: RefCell<Weak<Mutex<hidapi_rusb::HidApi>>>,
}

#[allow(dead_code)]
/// The transport struct. Holds a `Mutex` on the underlying `HidAPI` instance. Instantiate with
/// `new`.
pub struct TransportNativeHID {
    api_mutex: Arc<Mutex<hidapi_rusb::HidApi>>,
    device: HidDevice,
    guard: Mutex<i32>,
}

unsafe impl Send for HidApiWrapper {}

lazy_static! {
    static ref HIDAPIWRAPPER: Arc<Mutex<HidApiWrapper>> =
        Arc::new(Mutex::new(HidApiWrapper::new()));
}

impl HidApiWrapper {
    fn new() -> Self {
        HidApiWrapper {
            _api: RefCell::new(Weak::new()),
        }
    }

    fn get(&self) -> Result<Arc<Mutex<hidapi_rusb::HidApi>>, NativeTransportError> {
        let tmp = self._api.borrow().upgrade();
        if let Some(api_mutex) = tmp {
            return Ok(api_mutex);
        }

        let hidapi = hidapi_rusb::HidApi::new()?;
        let tmp = Arc::new(Mutex::new(hidapi));
        self._api.replace(Arc::downgrade(&tmp));
        Ok(tmp)
    }
}

impl TransportNativeHID {
    #[cfg(not(target_os = "linux"))]
    fn find_ledger_device_path(api: &hidapi_rusb::HidApi) -> Result<CString, NativeTransportError> {
        for device in api.device_list() {
            if device.vendor_id() == LEDGER_VID && device.usage_page() == LEDGER_USAGE_PAGE {
                return Ok(device.path().into());
            }
        }
        Err(NativeTransportError::DeviceNotFound)
    }

    #[cfg(target_os = "linux")]
    fn find_ledger_device_path(api: &hidapi_rusb::HidApi) -> Result<CString, NativeTransportError> {
        for device in api.device_list() {
            if device.vendor_id() == LEDGER_VID {
                return Ok(device.path().into());
            }
        }
        Err(NativeTransportError::DeviceNotFound)
    }

    /// Get the device path string
    #[allow(dead_code)]
    pub fn device_path(&self) -> Result<CString, NativeTransportError> {
        Self::find_ledger_device_path(&self.api_mutex.lock().unwrap())
    }

    /// Get a new TransportNativeHID by acquiring a lock on the global `hidapi_rusb::HidAPI`.
    /// Note that this may block forever if the resource is in use.
    pub fn new() -> Result<Self, NativeTransportError> {
        let apiwrapper = HIDAPIWRAPPER.lock().expect("Could not lock api wrapper");
        let api_mutex = apiwrapper.get().expect("Error getting api_mutex");
        let api = api_mutex.lock().expect("Could not lock");

        #[cfg(target_os = "android")]
        let device = {
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
                api.wrap_sys_device(usb_fd, -1)?
            } else {
                // Not sure how we should handle non-Termux Android here. This likely won't work.
                let device_path = TransportNativeHID::find_ledger_device_path(&api)?;
                api.open_path(&device_path)?
            }
        };

        #[cfg(not(target_os = "android"))]
        let device = {
            let device_path = TransportNativeHID::find_ledger_device_path(&api)?;
            api.open_path(&device_path)?
        };

        let ledger = TransportNativeHID {
            device,
            guard: Mutex::new(0),
            api_mutex: api_mutex.clone(),
        };

        Ok(ledger)
    }

    fn write_apdu(&self, channel: u16, apdu_command: &[u8]) -> Result<i32, NativeTransportError> {
        let command_length = apdu_command.len() as usize;
        let mut in_data = Vec::with_capacity(command_length + 2);
        in_data.push(((command_length >> 8) & 0xFF) as u8);
        in_data.push((command_length & 0xFF) as u8);
        in_data.extend_from_slice(apdu_command);

        let mut buffer = [0u8; LEDGER_PACKET_SIZE as usize];
        buffer[0] = ((channel >> 8) & 0xFF) as u8; // channel big endian
        buffer[1] = (channel & 0xFF) as u8; // channel big endian
        buffer[2] = 0x05u8;

        for (sequence_idx, chunk) in in_data
            .chunks((LEDGER_PACKET_SIZE - 5) as usize)
            .enumerate()
        {
            buffer[3] = ((sequence_idx >> 8) & 0xFF) as u8; // sequence_idx big endian
            buffer[4] = (sequence_idx & 0xFF) as u8; // sequence_idx big endian
            buffer[5..5 + chunk.len()].copy_from_slice(chunk);

            let result = self.device.write(&buffer);

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

    /// Read the 5-byte response header.
    fn read_response_header(
        rdr: &mut Cursor<&[u8]>,
    ) -> Result<(u16, u8, u16), NativeTransportError> {
        let rcv_channel = rdr.read_u16::<BigEndian>()?;
        let rcv_tag = rdr.read_u8()?;
        let rcv_seq_idx = rdr.read_u16::<BigEndian>()?;
        Ok((rcv_channel, rcv_tag, rcv_seq_idx))
    }

    /// Read a response APDU from the ledger channel.
    fn read_response_apdu(&self, _channel: u16) -> Result<Vec<u8>, NativeTransportError> {
        let mut response_buffer = [0u8; LEDGER_PACKET_SIZE as usize];
        let mut sequence_idx = 0u16;
        let mut expected_response_len = 0usize;
        let mut offset = 0;

        let mut answer_buf = vec![];

        loop {
            let res = self
                .device
                .read_timeout(&mut response_buffer, LEDGER_TIMEOUT)?;

            if (sequence_idx == 0 && res < 7) || res < 5 {
                return Err(NativeTransportError::Comm("Read error. Incomplete header"));
            }

            let mut rdr = Cursor::new(&response_buffer[..]);
            let (_, _, rcv_seq_idx) = Self::read_response_header(&mut rdr)?;

            // TODO: Check why windows returns a different channel/tag
            //        if rcv_channel != channel {
            //            return Err(Box::from(format!("Invalid channel: {}!={}", rcv_channel, channel )));
            //        }
            //        if rcv_tag != 0x05u8 {
            //            return Err(Box::from("Invalid tag"));
            //        }

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
        // acquire the internal communication lock
        let _guard = self.guard.lock().unwrap();

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

    // TODO: why does this exist?
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn close() {}
}

cfg_if! {
if #[cfg(target_os = "linux")] {
    const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

    #[repr(C)]
    #[doc(hidden)]
    pub struct HidrawReportDescriptor {
        size: u32,
        value: [u8; HID_MAX_DESCRIPTOR_SIZE],
    }

    #[cfg(not(target_os = "linux"))]
    fn get_usage_page(device_path: &CStr) -> Result<u16, NativeTransportError>
    {
        // #define HIDIOCGRDESCSIZE	_IOR('H', 0x01, int)
        // #define HIDIOCGRDESC		_IOR('H', 0x02, struct HidrawReportDescriptor)
        ioctl_read!(hid_read_descr_size, b'H', 0x01, libc::c_int);
        ioctl_read!(hid_read_descr, b'H', 0x02, HidrawReportDescriptor);

        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        use std::fs::OpenOptions;

        let file_name = device_path.to_str()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(file_name)?;

        let mut desc_size = 0;

        unsafe {
            let fd = file.as_raw_fd();

            hid_read_descr_size(fd, &mut desc_size)?;
            let mut desc_raw_uninit = mem::MaybeUninit::<HidrawReportDescriptor>::new(HidrawReportDescriptor {
                size: desc_size as u32,
                value: [0u8; 4096]
            });
            hid_read_descr(fd, desc_raw_uninit.as_mut_ptr())?;
            let desc_raw = desc_raw_uninit.assume_init();

            let data = &desc_raw.value[..desc_raw.size as usize];

            let mut data_len;
            let mut key_size;
            let mut i = 0 as usize;

            while i < desc_size as usize {
                let key = data[i];
                let key_cmd = key & 0xFC;

                if key & 0xF0 == 0xF0 {
                    data_len = 0;
                    key_size = 3;
                    if i + 1 < desc_size as usize {
                        data_len = data[i + 1];
                    }
                } else {
                    key_size = 1;
                    data_len = key & 0x03;
                    if data_len == 3 {
                        data_len = 4;
                    }
                }

                if key_cmd == 0x04 {
                    let usage_page = match data_len {
                        1 => u16::from(data[i + 1]),
                        2 => (u16::from(data[i + 2] )* 256 + u16::from(data[i + 1])),
                        _ => 0 as u16
                    };

                    return Ok(usage_page);
                }

                i += (data_len + key_size) as usize;
            }
        }
        Ok(0)
    }
}}

/*******************************************************************************
*   (c) 2018 ZondaX GmbH
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
