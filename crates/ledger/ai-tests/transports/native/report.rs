//! AI-written tests for the HID report framing. A submodule of
//! `src/transports/native/report.rs`.

use super::*;

/// A report as the device sends it, before framing checks.
type Raw = [u8; LEDGER_PACKET_READ_SIZE];

/// Reassembles the reports [`ApduCommand::packetize`] yields, checking the framing as the
/// device would. Whole APDUs land in `received`.
#[derive(Debug, Default)]
struct MockDevice {
    received: Vec<Vec<u8>>,
    pending: Vec<u8>,
    expected: usize,
    next_seq: u16,
}

impl MockDevice {
    fn write(&mut self, WriteReport(report): &WriteReport) -> Result<(), NativeTransportError> {
        assert_eq!(report[0], 0, "report id");
        assert_eq!(report[1..3], [0x01, 0x01], "channel");
        assert_eq!(report[3], 0x05, "tag");
        let got = u16::from_be_bytes([report[4], report[5]]);
        assert_eq!(got, self.next_seq, "sequence index");

        let mut payload = &report[6..];
        if got == 0 {
            self.expected = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            payload = &payload[2..];
            self.pending.clear();
        }
        let take = payload.len().min(self.expected - self.pending.len());
        self.pending.extend_from_slice(&payload[..take]);

        if self.pending.len() == self.expected {
            self.received.push(std::mem::take(&mut self.pending));
            self.next_seq = 0;
        } else {
            self.next_seq += 1;
        }
        Ok(())
    }
}

/// A command whose encoding is `len` bytes long, from 4 to 261. The data
/// field counts up from 0, so every byte position is distinguishable.
fn command(len: usize) -> ApduCommand {
    let data: Vec<u8> = (0..=255u8).cycle().take(255).collect();
    let builder = ApduCommand::builder().cla(0xe0).ins(0x06);
    let command = match len {
        4 => builder.build(),
        5 => builder.le(0).build(),
        6..=260 => builder.data(&data[..len - 5]).build(),
        261 => builder.data(&data).le(0).build(),
        _ => panic!("no short APDU is {len} bytes long"),
    }
    .unwrap();
    assert_eq!(command.as_bytes().len(), len);
    command
}

/// Collect the reports `command` packetizes to on the Ledger channel.
fn packets(command: &ApduCommand) -> Vec<[u8; LEDGER_PACKET_WRITE_SIZE]> {
    command.packetize(LEDGER_CHANNEL).map(|p| p.0).collect()
}

#[test]
fn short_apdu_fits_in_one_report() {
    let command = command(4);
    let p = packets(&command);
    assert_eq!(p.len(), 1);

    let mut expected = [0u8; LEDGER_PACKET_WRITE_SIZE];
    expected[1..3].copy_from_slice(&[0x01, 0x01]);
    expected[3] = 0x05;
    expected[4..6].copy_from_slice(&[0, 0]);
    expected[6..8].copy_from_slice(&[0, 4]);
    expected[8..12].copy_from_slice(&[0xe0, 0x06, 0x00, 0x00]);
    assert_eq!(p[0], expected);
}

#[test]
fn first_report_carries_57_bytes_and_the_rest_59() {
    assert_eq!(packets(&command(57)).len(), 1);

    let command_58 = command(58);
    let p = packets(&command_58);
    assert_eq!(p.len(), 2);
    assert_eq!(p[1][4..6], [0, 1], "second report has sequence index 1");
    assert_eq!(p[1][6], command_58.as_bytes()[57]);
    assert!(p[1][7..].iter().all(|&b| b == 0), "padding is zero");

    assert_eq!(packets(&command(57 + 59)).len(), 2);
    assert_eq!(packets(&command(57 + 59 + 1)).len(), 3);
}

#[test]
fn max_short_apdu_spans_five_reports_and_reassembles() {
    let command = command(261);
    let p = packets(&command);
    assert_eq!(p.len(), 5);

    let mut stream = Vec::new();
    for (i, report) in p.iter().enumerate() {
        assert_eq!(report[0], 0, "report id");
        assert_eq!(report[1..3], [0x01, 0x01], "channel");
        assert_eq!(report[3], 0x05, "tag");
        assert_eq!(report[4..6], (i as u16).to_be_bytes(), "sequence index");
        stream.extend_from_slice(&report[6..]);
    }
    assert_eq!(stream[..2], [0x01, 0x05], "length prefix is 261 big-endian");
    assert_eq!(&stream[2..2 + 261], command.as_bytes());
    assert!(stream[2 + 261..].iter().all(|&b| b == 0), "padding is zero");
}

#[test]
fn stale_payload_does_not_leak_into_a_shorter_report() {
    // The second report is partial. Its tail must be zero even though the
    // same packet array was full on the first report.
    let command = command(60);
    let p = packets(&command);
    assert_eq!(p.len(), 2);
    assert_eq!(p[1][6..9], command.as_bytes()[57..60]);
    assert!(p[1][9..].iter().all(|&b| b == 0));
}

#[test]
fn channel_is_big_endian() {
    let report = command(4).packetize(0xbeef).next().unwrap();
    assert_eq!(report.0[1..3], [0xbe, 0xef]);
}

#[test]
fn every_command_length_round_trips_through_a_device() {
    for len in 4..=261 {
        let command = command(len);
        let mut device = MockDevice::default();
        command
            .packetize(LEDGER_CHANNEL)
            .try_for_each(|p| device.write(&p))
            .unwrap();
        assert_eq!(
            device.received,
            vec![command.as_bytes().to_vec()],
            "length {len}"
        );
    }
}

#[test]
fn a_built_command_reaches_the_device_intact() {
    let cmd = crate::common::CommandBuilder::new()
        .cla(0xe0)
        .ins(0x04)
        .p1(0x80)
        .data(&[7; 200])
        .le(1)
        .build()
        .unwrap();
    let mut device = MockDevice::default();
    cmd.packetize(LEDGER_CHANNEL)
        .try_for_each(|p| device.write(&p))
        .unwrap();
    assert_eq!(device.received, vec![cmd.as_bytes().to_vec()]);
}

#[test]
fn two_commands_in_sequence_both_reassemble() {
    let (first, second) = (command(100), command(7));
    let mut device = MockDevice::default();
    first
        .packetize(LEDGER_CHANNEL)
        .try_for_each(|p| device.write(&p))
        .unwrap();
    second
        .packetize(LEDGER_CHANNEL)
        .try_for_each(|p| device.write(&p))
        .unwrap();
    assert_eq!(
        device.received,
        vec![first.as_bytes().to_vec(), second.as_bytes().to_vec()]
    );
}

// ---------------------------------------------------------------------------
// Read side

/// The reports the device sends for `response` on `channel`: the 2-byte
/// length, then the response, split over 64-byte reports of channel, tag,
/// sequence index and payload. Built by hand rather than with
/// [`ApduBuffer::packetize`], so the read side is checked against an
/// independent encoder.
fn device_reports(channel: u16, response: &[u8]) -> Vec<Raw> {
    let mut stream = (response.len() as u16).to_be_bytes().to_vec();
    stream.extend_from_slice(response);
    stream
        .chunks(LEDGER_PACKET_READ_SIZE - 5)
        .enumerate()
        .map(|(seq, chunk)| {
            let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
            report[..2].copy_from_slice(&channel.to_be_bytes());
            report[2] = LEDGER_TAG;
            report[3..5].copy_from_slice(&(seq as u16).to_be_bytes());
            report[5..5 + chunk.len()].copy_from_slice(chunk);
            report
        })
        .collect()
}

/// A report as a full read of `raw`.
fn full(raw: Raw) -> ReadReport {
    ReadReport {
        bytes: raw,
        len: raw.len(),
    }
}

/// Feed `reports` in order, starting from `progress`, collecting the payload, until the
/// reply is done or a report breaks framing. Panics if the reports run out
/// first, or if any are left over.
fn read_from(
    mut progress: Progress,
    reports: impl IntoIterator<Item = ReadReport>,
) -> Result<Vec<u8>, NativeTransportError> {
    let mut reports = reports.into_iter();
    let mut reply = Vec::new();
    while !progress.is_done() {
        let report = reports
            .next()
            .expect("ran out of reports before the reply was done");
        reply.extend_from_slice(&progress.accept(LEDGER_CHANNEL, report)?);
    }
    assert!(
        reports.next().is_none(),
        "reports left over after the reply"
    );
    Ok(reply)
}

/// Read a whole reply from `reports`, each a full read.
fn read_reply(reports: Vec<Raw>) -> Result<Vec<u8>, NativeTransportError> {
    read_from(Progress::START, reports.into_iter().map(full))
}

#[test]
fn one_report_response_hand_built() {
    let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
    report[..11].copy_from_slice(&[
        0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0x90, 0x00,
    ]);
    let reply = read_reply(vec![report]).unwrap();
    assert_eq!(reply, [0xde, 0xad, 0x90, 0x00]);
}

#[test]
fn two_report_response_hand_built() {
    // 60 bytes: 57 in the first report, 3 in the second.
    let response: Vec<u8> = (1..=60).collect();
    let mut first = [0u8; LEDGER_PACKET_READ_SIZE];
    first[..7].copy_from_slice(&[0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 60]);
    first[7..].copy_from_slice(&response[..57]);
    let mut second = [0u8; LEDGER_PACKET_READ_SIZE];
    second[..5].copy_from_slice(&[0x01, 0x01, 0x05, 0x00, 0x01]);
    second[5..8].copy_from_slice(&response[57..]);

    assert_eq!(read_reply(vec![first, second]).unwrap(), response);
}

#[test]
fn every_response_length_round_trips() {
    for len in 0..=ApduBuffer::CAPACITY {
        let response: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let reports = device_reports(LEDGER_CHANNEL, &response);
        assert_eq!(read_reply(reports).unwrap(), response, "length {len}");
    }
}

#[test]
fn only_the_bytes_read_are_payload() {
    // Short reads: the report array still holds stale bytes past `len`.
    let header = device_reports(LEDGER_CHANNEL, &[7; 20]).remove(0);
    let mut first = [0xaa; LEDGER_PACKET_READ_SIZE];
    // Header, length, and 3 payload bytes.
    first[..10].copy_from_slice(&header[..10]);
    let mut second = [0xaa; LEDGER_PACKET_READ_SIZE];
    second[..5].copy_from_slice(&[0x01, 0x01, 0x05, 0x00, 0x01]);
    second[5..22].fill(7);

    let reports = [
        ReadReport {
            bytes: first,
            len: 10,
        },
        ReadReport {
            bytes: second,
            len: 22,
        },
    ];
    assert_eq!(read_from(Progress::START, reports).unwrap(), [7; 20]);
}

#[test]
fn padding_past_the_response_length_is_dropped() {
    // A 2-byte response in a full 64-byte report: the rest is padding.
    let mut report = device_reports(LEDGER_CHANNEL, &[0x90, 0x00]).remove(0);
    report[9..].fill(0xaa);
    assert_eq!(read_reply(vec![report]).unwrap(), [0x90, 0x00]);
}

#[test]
fn response_longer_than_a_short_apdu_is_rejected_on_the_first_report() {
    // Length 262.
    let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
    report[..7].copy_from_slice(&[0x01, 0x01, 0x05, 0x00, 0x00, 0x01, 0x06]);
    let err = read_reply(vec![report]).unwrap_err();
    assert!(matches!(err, NativeTransportError::ResponseTooLong(262)));
}

#[test]
fn sequence_mismatch_is_detected() {
    let mut reports = device_reports(LEDGER_CHANNEL, &[1; 100]);
    reports[1][3..5].copy_from_slice(&[0, 2]);
    let err = read_reply(reports).unwrap_err();
    assert!(matches!(
        err,
        NativeTransportError::SequenceMismatch {
            got: 2,
            expected: 1
        }
    ));
}

#[test]
fn a_report_from_another_channel_is_rejected() {
    let reports = device_reports(0x0102, &[0x90, 0x00]);
    let err = read_reply(reports).unwrap_err();
    assert!(matches!(
        err,
        NativeTransportError::UnexpectedChannel {
            got: 0x0102,
            expected: LEDGER_CHANNEL
        }
    ));
}

#[test]
fn a_report_with_the_wrong_tag_is_rejected() {
    let mut reports = device_reports(LEDGER_CHANNEL, &[0x90, 0x00]);
    reports[0][2] = 0x06;
    let err = read_reply(reports).unwrap_err();
    assert!(matches!(err, NativeTransportError::UnexpectedTag(0x06)));
}

#[test]
fn truncated_reports_are_errors() {
    let report = device_reports(LEDGER_CHANNEL, &[0x90, 0x00]).remove(0);
    for len in [0, 4, 6] {
        let err = read_from(Progress::START, [ReadReport { bytes: report, len }]).unwrap_err();
        assert!(matches!(err, NativeTransportError::TruncatedReport(got) if got == len));
    }

    // A continuation report with no payload must not spin forever.
    let raw = device_reports(LEDGER_CHANNEL, &[1; 100]);
    let reports = [
        full(raw[0]),
        ReadReport {
            bytes: raw[1],
            len: 5,
        },
    ];
    let err = read_from(Progress::START, reports).unwrap_err();
    assert!(matches!(err, NativeTransportError::EmptyReport));
}

// ---------------------------------------------------------------------------
// Progress, which is what a device owes after a read fails

#[test]
fn nothing_is_done_before_the_first_report() {
    assert!(!Progress::START.is_done());
}

#[test]
fn an_empty_response_is_done_after_one_report() {
    let mut progress = Progress::START;
    let report = device_reports(LEDGER_CHANNEL, &[]).remove(0);
    let payload = progress.accept(LEDGER_CHANNEL, full(report)).unwrap();
    assert!(payload.is_empty());
    assert!(progress.is_done());
}

#[test]
fn progress_mid_reply_owes_the_rest_which_drains() {
    // 102 bytes: 57 in the first report, 45 in the second.
    let response: Vec<u8> = (0..102).collect();
    let reports = device_reports(LEDGER_CHANNEL, &response);

    let mut progress = Progress::START;
    let first = progress.accept(LEDGER_CHANNEL, full(reports[0])).unwrap();
    assert_eq!(*first, response[..57]);
    assert_eq!(
        progress,
        Progress {
            next_seq: 1,
            remaining: 45
        }
    );
    assert!(!progress.is_done());

    // Draining takes exactly the rest of the reply.
    let rest = read_from(progress, [full(reports[1])]).unwrap();
    assert_eq!(rest, response[57..]);
}

#[test]
fn progress_resumes_from_an_owed_state() {
    let response: Vec<u8> = (0..200).collect();
    let reports = device_reports(LEDGER_CHANNEL, &response);
    let mut owed = Progress {
        next_seq: 1,
        remaining: 200 - 57,
    };
    owed.accept(LEDGER_CHANNEL, full(reports[1])).unwrap();
    assert_eq!(
        owed,
        Progress {
            next_seq: 2,
            remaining: 84
        }
    );
}

#[test]
fn a_framing_error_leaves_progress_unchanged() {
    let mut reports = device_reports(LEDGER_CHANNEL, &[1; 100]);
    reports[1][0] = 0xbe;
    let mut progress = Progress::START;
    progress.accept(LEDGER_CHANNEL, full(reports[0])).unwrap();
    let before = progress;
    assert!(progress.accept(LEDGER_CHANNEL, full(reports[1])).is_err());
    assert_eq!(progress, before);
}
