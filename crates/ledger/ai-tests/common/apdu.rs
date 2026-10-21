//! AI-written tests for `ApduBuffer`. A submodule of `src/common/apdu.rs`.

use super::*;

fn buf(bytes: &[u8]) -> ApduBuffer {
    let mut b = ApduBuffer::new();
    b.extend_from_slice(bytes).unwrap();
    b
}

#[test]
fn starts_empty() {
    let b = ApduBuffer::new();
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    assert_eq!(b.remaining_capacity(), ApduBuffer::CAPACITY);
    assert_eq!(ApduBuffer::default(), b);
}

#[test]
fn append_tracks_length_and_contents() {
    let mut b = ApduBuffer::new();
    b.extend_from_slice(&[1, 2]).unwrap();
    b.extend_from_slice(&[3]).unwrap();
    assert_eq!(&*b, &[1, 2, 3]);
    assert_eq!(b.len(), 3);
    assert!(!b.is_empty());
    assert_eq!(b.remaining_capacity(), ApduBuffer::CAPACITY - 3);
}

#[test]
fn append_past_capacity_fails_and_changes_nothing() {
    let mut b = buf(&[9; ApduBuffer::CAPACITY - 1]);
    let before = b;
    assert_eq!(b.extend_from_slice(&[1, 2]), Err(BufferFull));
    assert_eq!(b, before);
    assert_eq!(b.len(), ApduBuffer::CAPACITY - 1);

    b.extend_from_slice(&[1]).unwrap();
    assert_eq!(b.remaining_capacity(), 0);
    assert_eq!(b.extend_from_slice(&[1]), Err(BufferFull));
    assert_eq!(b.extend_from_slice(&[]), Ok(()));
    assert_eq!(b.len(), ApduBuffer::CAPACITY);
}

#[test]
fn truncate_and_clear() {
    let mut b = buf(&[1, 2, 3, 4]);
    b.truncate(10);
    assert_eq!(&*b, &[1, 2, 3, 4]);
    b.truncate(2);
    assert_eq!(&*b, &[1, 2]);
    b.truncate(0);
    assert!(b.is_empty());

    let mut b = buf(&[1, 2, 3, 4]);
    b.clear();
    assert!(b.is_empty());
    assert_eq!(b.remaining_capacity(), ApduBuffer::CAPACITY);
}

#[test]
fn deref_mut_edits_live_bytes() {
    let mut b = buf(&[1, 2, 3]);
    b[1] = 9;
    assert_eq!(&*b, &[1, 9, 3]);
}

#[test]
fn equality_ignores_bytes_past_the_end() {
    let mut shrunk = buf(&[1, 2, 3, 4, 5, 6]);
    shrunk.truncate(2);
    assert_eq!(shrunk, buf(&[1, 2]));
    assert_ne!(shrunk, buf(&[1, 2, 3]));
    assert_ne!(buf(&[1]), buf(&[2]));
}

#[test]
fn debug_shows_the_length_not_the_contents() {
    let b = buf(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(format!("{b:?}"), "ApduBuffer { bytes: 4, .. }");
}
