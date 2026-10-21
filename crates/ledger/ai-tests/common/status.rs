//! AI-written tests for `StatusWord`. A submodule of `src/common/status.rs`.

use super::*;

#[test]
fn status_word_bytes() {
    let sw = StatusWord::from_be_bytes([0x69, 0x85]);
    assert_eq!(sw, StatusWord::CONDITIONS_NOT_SATISFIED);
    assert_eq!(sw.raw(), 0x6985);
    assert_eq!(sw.sw1(), 0x69);
    assert_eq!(sw.sw2(), 0x85);
    assert_eq!(sw.to_be_bytes(), [0x69, 0x85]);
    assert_eq!(StatusWord::from([0x90, 0x00]), StatusWord::SUCCESS);
    assert_eq!(u16::from(StatusWord::BUSY), 0x9001);
}

#[test]
fn status_word_success() {
    assert!(StatusWord::SUCCESS.is_success());
    assert!(!StatusWord::RESULT_OK.is_success());
    assert!(!StatusWord::BUSY.is_success());
    assert!(!StatusWord::new(0x9000 + 1).is_success());
}

#[test]
fn status_word_payload_classes() {
    let sw = StatusWord::new(0x63C3);
    assert_eq!(sw.pin_attempts_remaining(), Some(3));
    assert_eq!(StatusWord::VERIFY_FAILED.pin_attempts_remaining(), Some(0));
    assert_eq!(StatusWord::new(0x63F1).pin_attempts_remaining(), None);
    assert_eq!(StatusWord::SUCCESS.pin_attempts_remaining(), None);

    assert_eq!(StatusWord::new(0x6C41).correct_length(), Some(0x41));
    assert_eq!(StatusWord::INCORRECT_P3_LENGTH.correct_length(), Some(0));
    assert_eq!(StatusWord::WRONG_LENGTH.correct_length(), None);

    assert_eq!(StatusWord::new(0x6110).bytes_available(), Some(0x10));
    assert_eq!(StatusWord::SUCCESS.bytes_available(), None);
}

#[test]
fn status_word_descriptions() {
    assert_eq!(StatusWord::SUCCESS.description(), "Success");
    assert_eq!(StatusWord::LOCKED_DEVICE.description(), "Device locked");
    assert_eq!(
        StatusWord::new(0x63C5).description(),
        StatusWord::VERIFY_FAILED.description()
    );
    // Unknown codes fall back to their class.
    assert_eq!(
        StatusWord::new(0x6A99).description(),
        "Unknown wrong parameters error"
    );
    assert_eq!(
        StatusWord::new(0xB007).description(),
        "App-specific status word"
    );
    assert_eq!(StatusWord::new(0x1234).description(), "Unknown status word");
}

#[test]
fn status_word_formatting() {
    let sw = StatusWord::CONDITIONS_NOT_SATISFIED;
    assert!(sw.to_string().starts_with("0x6985 ("));
    assert_eq!(format!("{sw:?}"), "StatusWord(0x6985)");
    assert_eq!(format!("{sw:x}"), "6985");
    assert_eq!(format!("{sw:#06X}"), "0x6985");
    assert_eq!(
        format!("{:?}", StatusWord::new(0x0001)),
        "StatusWord(0x0001)"
    );
}

#[test]
fn status_word_consts_match_patterns() {
    let sw = StatusWord::new(0x6985);
    assert!(matches!(sw, StatusWord::CONDITIONS_NOT_SATISFIED));
    assert!(!matches!(sw, StatusWord::SUCCESS));
}
