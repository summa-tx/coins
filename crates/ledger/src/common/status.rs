use std::fmt;

/// An APDU status word: the trailing two bytes of every response.
///
/// Status words follow ISO 7816-4. The first byte (SW1) is the class and the
/// second (SW2) is the detail. Only [`StatusWord::SUCCESS`] indicates success.
///
/// The set of codes a device can return is open: the OS defines the codes in
/// this type, and each app may define its own in the ranges the OS reserves
/// for it. This type therefore never fails to parse. Unknown codes still carry
/// their class, which [`StatusWord::description`] falls back to.
///
/// The named constants mirror `include/status_words.h` in the Ledger secure
/// SDK, plus the handful of codes the BOLOS dashboard emits when no app is
/// open. App-specific codes are deliberately not included.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusWord(u16);

impl fmt::Debug for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusWord({:#06x})", self.0)
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x} ({})", self.0, self.description())
    }
}

// Proprietary OS codes.
impl StatusWord {
    /// The device is locked. The PIN has not been entered.
    ///
    /// SDK name: `SWO_SEC_PIN_15`.
    pub const LOCKED_DEVICE: Self = Self(0x5515);

    /// The device is locked.
    ///
    /// Undocumented. Observed from locked devices on older firmware. Current
    /// firmware returns [`StatusWord::LOCKED_DEVICE`] instead.
    pub const LEGACY_LOCKED_DEVICE: Self = Self(0x6804);
}

// Codes emitted by the BOLOS dashboard. These are documented by Ledger's JS
// libraries rather than the SDK header.
impl StatusWord {
    /// The user refused the request on the device.
    pub const USER_REFUSED_ON_DEVICE: Self = Self(0x5501);

    /// The device is in recovery mode.
    pub const DEVICE_IN_RECOVERY_MODE: Self = Self(0x662F);

    /// The device has not been onboarded. A second code with the same
    /// meaning as [`StatusWord::DEVICE_NOT_ONBOARDED`]; the name follows
    /// Ledger's JS libraries.
    pub const DEVICE_NOT_ONBOARDED_2: Self = Self(0x6611);

    /// The dashboard did not recognize the APDU. Usually no app is open.
    pub const UNKNOWN_APDU: Self = Self(0x6D02);

    /// The device has not been onboarded.
    pub const DEVICE_NOT_ONBOARDED: Self = Self(0x6D07);

    /// The device has halted.
    pub const HALTED: Self = Self(0x6FAA);
}

// ISO 7816-4 codes, as listed in the SDK header.
impl StatusWord {
    /// The APDU was accepted and the answer will arrive later, e.g. after
    /// user approval.
    pub const NO_RESPONSE: Self = Self(0x0000);

    /// Normal processing. SW2 is the number of response bytes still available.
    pub const RESPONSE_BYTES_AVAILABLE: Self = Self(0x6100);

    /// Warning: the returned data may be corrupted.
    pub const DATA_MAY_BE_CORRUPTED: Self = Self(0x6281);
    /// Warning: end of file reached before reading Le bytes.
    pub const EOF_REACHED_BEFORE_LE: Self = Self(0x6282);
    /// Warning: the selected file has been invalidated.
    pub const SELECTED_FILE_INVALIDATED: Self = Self(0x6283);
    /// Warning: the selected file is invalid.
    pub const SELECTED_FILE_INVALID: Self = Self(0x6284);
    /// Warning: no input data available.
    pub const NO_INPUT_DATA_AVAILABLE: Self = Self(0x6285);

    /// The card key is not supported.
    pub const CARD_KEY_NOT_SUPPORTED: Self = Self(0x6382);
    /// The reader key is not supported.
    pub const READER_KEY_NOT_SUPPORTED: Self = Self(0x6383);
    /// Plaintext transmission is not supported.
    pub const PLAINTEXT_TRANS_NOT_SUPPORTED: Self = Self(0x6384);
    /// Secured transmission is not supported.
    pub const SECURED_TRANS_NOT_SUPPORTED: Self = Self(0x6385);
    /// Volatile memory is not available.
    pub const VOLATILE_MEM_NOT_AVAILABLE: Self = Self(0x6386);
    /// Non-volatile memory is not available.
    pub const NON_VOLATILE_MEM_NOT_AVAILABLE: Self = Self(0x6387);
    /// The key number is invalid.
    pub const KEY_NUMBER_INVALID: Self = Self(0x6388);
    /// The key length is incorrect.
    pub const KEY_LENGTH_INCORRECT: Self = Self(0x6389);
    /// PIN verification failed. The low nibble of SW2 is the number of
    /// attempts remaining. See [`StatusWord::pin_attempts_remaining`].
    pub const VERIFY_FAILED: Self = Self(0x63C0);
    /// More data is expected.
    pub const MORE_DATA_EXPECTED: Self = Self(0x63F1);

    /// Execution error. Persistent memory is unchanged.
    pub const EXECUTION_ERROR: Self = Self(0x6400);
    /// The command timed out.
    pub const COMMAND_TIMEOUT: Self = Self(0x6401);

    /// Memory write error.
    pub const MEMORY_WRITE_ERROR: Self = Self(0x6501);
    /// Memory failure.
    pub const MEMORY_FAILURE: Self = Self(0x6581);

    /// Security issue.
    pub const SECURITY_ISSUE: Self = Self(0x6600);
    /// Receive error: parity.
    pub const RECEIVE_ERROR_PARITY: Self = Self(0x6601);
    /// Wrong checksum.
    pub const WRONG_CHECKSUM: Self = Self(0x6602);
    /// Incorrect padding.
    pub const INCORRECT_PADDING: Self = Self(0x6669);

    /// Wrong length.
    pub const WRONG_LENGTH: Self = Self(0x6700);

    /// Functions in CLA not supported. No further information.
    pub const NOT_SUPPORTED_ERROR_NO_INFO: Self = Self(0x6800);
    /// Logical channels are not supported.
    pub const LOGICAL_CHANNEL_NOT_SUPPORTED: Self = Self(0x6881);
    /// Secure messaging is not supported.
    pub const SECURE_MESSAGING_NOT_SUPPORTED: Self = Self(0x6882);
    /// The last command of the chain was expected.
    pub const LAST_COMMAND_OF_CHAIN_EXPECTED: Self = Self(0x6883);
    /// Command chaining is not supported.
    pub const COMMAND_CHAINING_NOT_SUPPORTED: Self = Self(0x6884);

    /// Command not allowed. No further information.
    pub const COMMAND_ERROR_NO_INFO: Self = Self(0x6900);
    /// The command was not accepted.
    pub const COMMAND_NOT_ACCEPTED: Self = Self(0x6901);
    /// The command is not allowed.
    pub const COMMAND_NOT_ALLOWED: Self = Self(0x6980);
    /// The command is incompatible with the file structure.
    pub const SUBCOMMAND_NOT_ALLOWED: Self = Self(0x6981);
    /// Security status not satisfied. The device may be locked, or the caller
    /// may lack access rights.
    pub const SECURITY_CONDITION_NOT_SATISFIED: Self = Self(0x6982);
    /// The authentication method is blocked.
    pub const AUTH_METHOD_BLOCKED: Self = Self(0x6983);
    /// The referenced data has been invalidated.
    pub const REFERENCED_DATA_BLOCKED: Self = Self(0x6984);
    /// Conditions of use not satisfied. Apps typically return this when the
    /// user rejects the request on the device.
    pub const CONDITIONS_NOT_SATISFIED: Self = Self(0x6985);
    /// Command not allowed: no current EF.
    pub const COMMAND_NOT_ALLOWED_EF: Self = Self(0x6986);
    /// An expected secure messaging object is missing.
    pub const EXPECTED_SECURE_MSG_OBJ_MISSING: Self = Self(0x6987);
    /// A secure messaging data object is incorrect.
    pub const INCORRECT_SECURE_MSG_DATA_OBJ: Self = Self(0x6988);
    /// Permission denied.
    pub const PERMISSION_DENIED: Self = Self(0x69F0);
    /// Missing privileges.
    pub const MISSING_PRIVILEGES: Self = Self(0x69F1);

    /// Wrong parameters. No further information.
    pub const PARAMETER_ERROR_NO_INFO: Self = Self(0x6A00);
    /// The parameters in the data field are incorrect.
    pub const INCORRECT_DATA: Self = Self(0x6A80);
    /// The function is not supported.
    pub const FUNCTION_NOT_SUPPORTED: Self = Self(0x6A81);
    /// File not found.
    pub const FILE_NOT_FOUND: Self = Self(0x6A82);
    /// Record not found.
    pub const RECORD_NOT_FOUND: Self = Self(0x6A83);
    /// Not enough memory space.
    pub const INSUFFICIENT_MEMORY: Self = Self(0x6A84);
    /// Lc is inconsistent with the TLV structure.
    pub const INCONSISTENT_TLV_STRUCT: Self = Self(0x6A85);
    /// Incorrect parameters P1-P2.
    pub const INCORRECT_P1_P2: Self = Self(0x6A86);
    /// Lc is inconsistent with P1-P2.
    pub const WRONG_DATA_LENGTH: Self = Self(0x6A87);
    /// Referenced data not found.
    pub const REFERENCED_DATA_NOT_FOUND: Self = Self(0x6A88);
    /// File already exists.
    pub const FILE_ALREADY_EXISTS: Self = Self(0x6A89);
    /// DF name already exists.
    pub const DF_NAME_ALREADY_EXISTS: Self = Self(0x6A8A);
    /// Wrong parameter value.
    pub const WRONG_PARAMETER_VALUE: Self = Self(0x6AF0);

    /// Wrong parameters P1-P2.
    pub const WRONG_P1_P2: Self = Self(0x6B00);

    /// Wrong Le field. SW2 is the correct length. See
    /// [`StatusWord::correct_length`].
    pub const INCORRECT_P3_LENGTH: Self = Self(0x6C00);

    /// The instruction code is not supported or invalid.
    pub const INVALID_INS: Self = Self(0x6D00);

    /// The instruction class is not supported.
    pub const INVALID_CLA: Self = Self(0x6E00);

    /// No precise diagnosis.
    pub const UNKNOWN: Self = Self(0x6F00);

    /// Success.
    pub const SUCCESS: Self = Self(0x9000);
    /// The device is busy.
    pub const BUSY: Self = Self(0x9001);
    /// The PIN was not successfully verified.
    ///
    /// SDK name: `SWO_PIN_NOT_SUCCESFULLY_VERIFIED`.
    pub const PIN_NOT_SUCCESSFULLY_VERIFIED: Self = Self(0x9004);
    /// Legacy success code. Not treated as success by
    /// [`StatusWord::is_success`].
    pub const RESULT_OK: Self = Self(0x9100);
    /// Wrong state status.
    pub const STATES_STATUS_WRONG: Self = Self(0x9101);
    /// Transaction limit reached.
    pub const TRANSACTION_LIMIT_REACHED: Self = Self(0x9102);
    /// Insufficient memory for the command.
    pub const INSUFFICIENT_MEM_FOR_CMD: Self = Self(0x910E);
    /// The command code is not supported.
    pub const COMMAND_CODE_NOT_SUPPORTED: Self = Self(0x911C);
    /// Invalid key number.
    pub const INVALID_KEY_NUMBER: Self = Self(0x9140);
    /// Wrong length for the instruction.
    pub const WRONG_LENGTH_FOR_INS: Self = Self(0x917E);
    /// No EF selected.
    pub const NO_EF_SELECTED: Self = Self(0x9400);
    /// Address range exceeded.
    pub const ADDRESS_RANGE_EXCEEDED: Self = Self(0x9402);
    /// FID not found.
    pub const FID_NOT_FOUND: Self = Self(0x9404);
    /// Parse error.
    pub const PARSE_ERROR: Self = Self(0x9405);
    /// No PIN defined.
    pub const NO_PIN_DEFINED: Self = Self(0x9802);
    /// Access condition not fulfilled.
    pub const ACCESS_CONDITION_NOT_FULFILLED: Self = Self(0x9804);
}

impl StatusWord {
    /// Instantiate from the raw 16-bit code.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Parse from the big-endian wire representation.
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// The big-endian wire representation.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// The raw 16-bit code.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// The first byte: the class.
    pub const fn sw1(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// The second byte: the detail.
    pub const fn sw2(self) -> u8 {
        self.0 as u8
    }

    /// True if the status word is [`StatusWord::SUCCESS`].
    pub const fn is_success(self) -> bool {
        self.0 == Self::SUCCESS.0
    }

    /// For [`StatusWord::VERIFY_FAILED`] and its variants, the number of PIN
    /// attempts remaining. `None` for any other status word.
    pub const fn pin_attempts_remaining(self) -> Option<u8> {
        if self.0 & 0xFFF0 == Self::VERIFY_FAILED.0 {
            Some(self.sw2() & 0x0F)
        } else {
            None
        }
    }

    /// For the [`StatusWord::INCORRECT_P3_LENGTH`] class, the correct Le
    /// value. `None` for any other status word.
    pub const fn correct_length(self) -> Option<u8> {
        if self.sw1() == Self::INCORRECT_P3_LENGTH.sw1() {
            Some(self.sw2())
        } else {
            None
        }
    }

    /// For the [`StatusWord::RESPONSE_BYTES_AVAILABLE`] class, the number of
    /// response bytes still available. `None` for any other status word.
    pub const fn bytes_available(self) -> Option<u8> {
        if self.sw1() == Self::RESPONSE_BYTES_AVAILABLE.sw1() {
            Some(self.sw2())
        } else {
            None
        }
    }

    /// A human-readable description of the status word. Known codes get a
    /// specific description. Unknown codes fall back to a description of
    /// their class.
    pub const fn description(self) -> &'static str {
        match self.0 {
            0x5501 => "User refused on device",
            0x5515 => "Device locked",
            0x6804 => "Device locked (legacy code)",
            0x662F => "Device in recovery mode",
            0x6611 | 0x6D07 => "Device not onboarded",
            0x6D02 => "Unknown APDU. Hint: is an app open on the device?",
            0x6FAA => "Device halted",

            0x0000 => "No response yet; the answer will arrive later",
            0x6100..=0x61FF => {
                "Normal processing; SW2 is the number of response bytes still available"
            }
            0x6281 => "Warning: returned data may be corrupted",
            0x6282 => "Warning: end of file reached before reading Le bytes",
            0x6283 => "Warning: selected file invalidated",
            0x6284 => "Warning: selected file invalid",
            0x6285 => "Warning: no input data available",
            0x6382 => "Card key not supported",
            0x6383 => "Reader key not supported",
            0x6384 => "Plaintext transmission not supported",
            0x6385 => "Secured transmission not supported",
            0x6386 => "Volatile memory not available",
            0x6387 => "Non-volatile memory not available",
            0x6388 => "Key number invalid",
            0x6389 => "Key length incorrect",
            0x63C0..=0x63CF => {
                "PIN verification failed; low nibble of SW2 is the attempts remaining"
            }
            0x63F1 => "More data expected",
            0x6400 => "Execution error; persistent memory unchanged",
            0x6401 => "Command timeout",
            0x6501 => "Memory write error",
            0x6581 => "Memory failure",
            0x6600 => "Security issue",
            0x6601 => "Receive error: parity",
            0x6602 => "Wrong checksum",
            0x6669 => "Incorrect padding",
            0x6700 => "Wrong length",
            0x6800 => "Functions in CLA not supported",
            0x6881 => "Logical channel not supported",
            0x6882 => "Secure messaging not supported",
            0x6883 => "Last command of chain expected",
            0x6884 => "Command chaining not supported",
            0x6900 => "Command not allowed",
            0x6901 => "Command not accepted",
            0x6980 => "Command not allowed",
            0x6981 => "Command incompatible with file structure",
            0x6982 => "Security status not satisfied. Hint: is the device locked?",
            0x6983 => "Authentication method blocked",
            0x6984 => "Referenced data invalidated",
            0x6985 => "Conditions of use not satisfied. Hint: did the user reject the request?",
            0x6986 => "Command not allowed; no current EF",
            0x6987 => "Expected secure messaging object missing",
            0x6988 => "Incorrect secure messaging data object",
            0x69F0 => "Permission denied",
            0x69F1 => "Missing privileges",
            0x6A00 => "Wrong parameters",
            0x6A80 => "Incorrect parameters in the data field",
            0x6A81 => "Function not supported",
            0x6A82 => "File not found",
            0x6A83 => "Record not found",
            0x6A84 => "Not enough memory space",
            0x6A85 => "Lc inconsistent with TLV structure",
            0x6A86 => "Incorrect parameters P1-P2",
            0x6A87 => "Lc inconsistent with P1-P2",
            0x6A88 => "Referenced data not found",
            0x6A89 => "File already exists",
            0x6A8A => "DF name already exists",
            0x6AF0 => "Wrong parameter value",
            0x6B00 => "Wrong parameters P1-P2",
            0x6C00..=0x6CFF => "Wrong Le field; SW2 is the correct length",
            0x6D00 => "Instruction not supported. Hint: is the correct app open on the device?",
            0x6E00 => "Class not supported. Hint: is the correct app open on the device?",
            0x6F00 => "No precise diagnosis",
            0x9000 => "Success",
            0x9001 => "Device busy",
            0x9004 => "PIN not successfully verified",
            0x9100 => "Result OK (legacy)",
            0x9101 => "Wrong state status",
            0x9102 => "Transaction limit reached",
            0x910E => "Insufficient memory for command",
            0x911C => "Command code not supported",
            0x9140 => "Invalid key number",
            0x917E => "Wrong length for instruction",
            0x9400 => "No EF selected",
            0x9402 => "Address range exceeded",
            0x9404 => "FID not found",
            0x9405 => "Parse error",
            0x9802 => "No PIN defined",
            0x9804 => "Access condition not fulfilled",

            _ => match self.sw1() {
                0x62 => "Unknown warning; persistent memory unchanged",
                0x63 => "Unknown warning; persistent memory changed",
                0x64 => "Unknown execution error; persistent memory unchanged",
                0x65 => "Unknown execution error; persistent memory changed",
                0x66 => "Unknown security issue",
                0x67 => "Unknown wrong length error",
                0x68 => "Unknown unsupported CLA function",
                0x69 => "Unknown command not allowed error",
                0x6A => "Unknown wrong parameters error",
                0x6B => "Unknown wrong P1-P2 error",
                0x6D => "Unknown unsupported instruction error",
                0x6E => "Unknown unsupported class error",
                0x6F => "Unknown error with no diagnosis",
                0xB0..=0xEF => "App-specific status word",
                _ => "Unknown status word",
            },
        }
    }
}

#[cfg(test)]
#[path = "../../ai-tests/common/status.rs"]
mod ai_tests;
