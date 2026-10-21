//! AI-written tests for `ApduCommand` and `CommandBuilder`. A submodule of
//! `src/common/command.rs`.

use super::*;

/// A builder for the Ethereum app's CLA with the given instruction.
fn eth(ins: u8) -> CommandBuilder<'static> {
    CommandBuilder::new().cla(0xe0).ins(ins)
}

#[test]
fn header_only() {
    let cmd = eth(0x06).p1(0x01).p2(0x02).build().unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x06, 0x01, 0x02]);
    assert_eq!(cmd.cla(), 0xe0);
    assert_eq!(cmd.ins(), 0x06);
    assert_eq!(cmd.p1(), 0x01);
    assert_eq!(cmd.p2(), 0x02);
    assert!(cmd.data().is_empty());
    assert_eq!(cmd.le(), None);
}

#[test]
fn builder_requires_cla_and_ins() {
    assert!(matches!(
        CommandBuilder::new().build(),
        Err(LedgerError::MissingCla)
    ));
    assert!(matches!(
        CommandBuilder::default().build(),
        Err(LedgerError::MissingCla)
    ));
    assert!(
        matches!(
            CommandBuilder::new().ins(0x06).build(),
            Err(LedgerError::MissingCla)
        ),
        "CLA is checked before INS"
    );
    assert!(matches!(
        ApduCommand::builder().cla(0xe0).build(),
        Err(LedgerError::MissingIns)
    ));
    assert!(matches!(
        CommandBuilder::new()
            .cla(0xe0)
            .p1(1)
            .p2(2)
            .data(&[1])
            .le(1)
            .build(),
        Err(LedgerError::MissingIns)
    ));
}

#[test]
fn p1_p2_default_to_zero() {
    let cmd = CommandBuilder::new().cla(0).ins(0).build().unwrap();
    assert_eq!(cmd.as_bytes(), &[0, 0, 0, 0]);
}

#[test]
fn le_without_data_is_not_mistaken_for_lc() {
    let cmd = eth(0x06).le(0x10).build().unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x06, 0, 0, 0x10]);
    assert!(cmd.data().is_empty());
    assert_eq!(cmd.le(), Some(0x10));
}

#[test]
fn data_round_trip() {
    let payload = [1u8, 2, 3];
    let cmd = eth(0x02).data(&payload).build().unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 3, 1, 2, 3]);
    assert_eq!(cmd.data(), &payload);
    assert_eq!(cmd.le(), None);

    let cmd = eth(0x02).data(&payload).le(0xff).build().unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 3, 1, 2, 3, 0xff]);
    assert_eq!(cmd.data(), &payload);
    assert_eq!(cmd.le(), Some(0xff));
}

#[test]
fn empty_data_encodes_no_lc() {
    let with_empty = eth(0x02).data(&[]).build().unwrap();
    let without = eth(0x02).build().unwrap();
    assert_eq!(with_empty, without);
    assert_eq!(with_empty.as_bytes(), &[0xe0, 0x02, 0, 0]);
}

#[test]
fn set_data_replaces_payload_and_keeps_le() {
    let mut cmd = eth(0x02).data(&[9, 9, 9, 9]).le(7).build().unwrap();
    cmd.set_data(&[1, 2]).unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 2, 1, 2, 7]);

    cmd.set_data(&[]).unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 7]);
    assert!(cmd.data().is_empty());
    assert_eq!(cmd.le(), Some(7));
}

#[test]
fn set_le_adds_replaces_and_clears() {
    let mut cmd = eth(0x02).data(&[5]).build().unwrap();
    cmd.set_le(Some(1));
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 1, 5, 1]);
    cmd.set_le(Some(2));
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 1, 5, 2]);
    cmd.set_le(None);
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 1, 5]);
    cmd.set_le(None);
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x02, 0, 0, 1, 5]);
}

#[test]
fn header_setters_touch_only_the_header() {
    let mut cmd = CommandBuilder::new()
        .cla(0)
        .ins(0)
        .data(&[0xaa])
        .build()
        .unwrap();
    cmd.set_cla(0xe0);
    cmd.set_ins(0x04);
    cmd.set_p1(0x80);
    cmd.set_p2(0x01);
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x04, 0x80, 0x01, 1, 0xaa]);
}

#[test]
fn data_length_limit() {
    let max = [0u8; ApduCommand::MAX_DATA_LEN];
    let cmd = eth(0x04).data(&max).build().unwrap();
    assert_eq!(cmd.len(), 4 + 1 + 255);
    let cmd = eth(0x04).data(&max).le(0).build().unwrap();
    assert_eq!(cmd.len(), 4 + 1 + 255 + 1);

    let too_long = [0u8; ApduCommand::MAX_DATA_LEN + 1];
    assert!(matches!(
        eth(0x04).data(&too_long).build(),
        Err(LedgerError::DataTooLong(256))
    ));

    let before = eth(0x04).data(&[1]).build().unwrap();
    let mut cmd = before;
    assert!(matches!(
        cmd.set_data(&too_long),
        Err(LedgerError::DataTooLong(256))
    ));
    assert_eq!(
        cmd, before,
        "a rejected set_data leaves the command unchanged"
    );
}

#[test]
fn equality_ignores_stale_bytes_past_the_end() {
    let mut shrunk = eth(0x02).data(&[1, 2, 3, 4, 5, 6, 7, 8]).build().unwrap();
    shrunk.set_data(&[]).unwrap();
    let fresh = eth(0x02).build().unwrap();
    assert_eq!(shrunk, fresh);
}

#[test]
fn builder_is_reusable() {
    let base = eth(0x04);
    let first = base.p1(0x00).data(&[1]).build().unwrap();
    let more = base.p1(0x80).data(&[2]).build().unwrap();
    assert_eq!(first.as_bytes(), &[0xe0, 0x04, 0x00, 0, 1, 1]);
    assert_eq!(more.as_bytes(), &[0xe0, 0x04, 0x80, 0, 1, 2]);
}

#[test]
fn builder_is_const_constructible() {
    const GET_VERSION: CommandBuilder<'static> = CommandBuilder::new().cla(0xe0).ins(0x06);
    let cmd = GET_VERSION.build().unwrap();
    assert_eq!(cmd.as_bytes(), &[0xe0, 0x06, 0, 0]);
}
