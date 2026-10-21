//! AI-written tests for `ApduAnswer`. A submodule of `src/common/answer.rs`.

use super::*;

fn buf(bytes: &[u8]) -> ApduBuffer {
    let mut b = ApduBuffer::new();
    b.extend_from_slice(bytes).unwrap();
    b
}

#[test]
fn shorter_than_a_status_word_is_an_error() {
    assert!(matches!(
        ApduAnswer::from_answer(buf(&[])),
        Err(LedgerError::ResponseTooShort(0))
    ));
    assert!(matches!(
        ApduAnswer::from_answer(buf(&[0x90])),
        Err(LedgerError::ResponseTooShort(1))
    ));
}

#[test]
fn status_is_the_trailing_two_bytes() {
    let answer = ApduAnswer::from_answer(buf(&[1, 2, 0x69, 0x85])).unwrap();
    assert_eq!(answer.status(), StatusWord::CONDITIONS_NOT_SATISFIED);
    assert!(!answer.is_success());
    assert_eq!(answer.data(), &[1, 2]);
}

#[test]
fn bare_status_word_has_empty_data() {
    let answer = ApduAnswer::from_answer(buf(&[0x90, 0x00])).unwrap();
    assert!(answer.is_success());
    assert!(answer.data().is_empty());
}

#[test]
fn unknown_status_is_kept_verbatim() {
    let answer = ApduAnswer::from_answer(buf(&[0xb0, 0x07])).unwrap();
    assert_eq!(answer.status().raw(), 0xb007);
    assert!(!answer.is_success());
}

#[test]
fn largest_response_fits() {
    let mut bytes = vec![0x11; ApduBuffer::CAPACITY - 2];
    bytes.extend_from_slice(&[0x90, 0x00]);
    let answer = ApduAnswer::from_answer(buf(&bytes)).unwrap();
    assert_eq!(answer.data().len(), ApduBuffer::CAPACITY - 2);
    assert!(answer.is_success());
}

#[test]
fn deref_is_the_whole_response() {
    let answer = ApduAnswer::from_answer(buf(&[7, 8, 0x90, 0x00])).unwrap();
    assert_eq!(&*answer, &[7, 8, 0x90, 0x00]);
    assert_eq!(answer.len(), 4);
}
