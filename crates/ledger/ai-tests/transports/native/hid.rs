//! AI-written tests for the HID framing. A submodule of
//! `src/transports/native/hid.rs`.

use super::*;

/// Reassembles the reports `packetize` emits, checking the framing as the
/// device would. Whole APDUs land in `received`.
#[derive(Debug, Default)]
struct MockDevice {
    received: Vec<Vec<u8>>,
    pending: Vec<u8>,
    expected: usize,
    next_seq: u16,
}

impl MockDevice {
    fn write(&mut self, report: &WriteReport) -> Result<(), NativeTransportError> {
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

/// Collect the reports `packetize` produces for `apdu` on the Ledger channel.
fn packets(apdu: &[u8]) -> Vec<WriteReport> {
    let mut out = Vec::new();
    packetize(LEDGER_CHANNEL, apdu, |p| {
        out.push(*p);
        Ok(())
    })
    .unwrap();
    out
}

#[test]
fn short_apdu_fits_in_one_report() {
    let apdu = [0xe0, 0x06, 0x00, 0x00];
    let p = packets(&apdu);
    assert_eq!(p.len(), 1);

    let mut expected = [0u8; LEDGER_PACKET_WRITE_SIZE];
    expected[1..3].copy_from_slice(&[0x01, 0x01]);
    expected[3] = 0x05;
    expected[4..6].copy_from_slice(&[0, 0]);
    expected[6..8].copy_from_slice(&[0, 4]);
    expected[8..12].copy_from_slice(&apdu);
    assert_eq!(p[0], expected);
}

#[test]
fn first_report_carries_57_bytes_and_the_rest_59() {
    assert_eq!(packets(&[0xab; 57]).len(), 1);

    let p = packets(&[0xab; 58]);
    assert_eq!(p.len(), 2);
    assert_eq!(p[1][4..6], [0, 1], "second report has sequence index 1");
    assert_eq!(p[1][6], 0xab);
    assert!(p[1][7..].iter().all(|&b| b == 0), "padding is zero");

    assert_eq!(packets(&[0; 57 + 59]).len(), 2);
    assert_eq!(packets(&[0; 57 + 59 + 1]).len(), 3);
}

#[test]
fn max_short_apdu_spans_five_reports_and_reassembles() {
    let apdu: Vec<u8> = (0..=255u8).cycle().take(261).collect();
    let p = packets(&apdu);
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
    assert_eq!(&stream[2..2 + 261], &apdu[..]);
    assert!(stream[2 + 261..].iter().all(|&b| b == 0), "padding is zero");
}

#[test]
fn stale_payload_does_not_leak_into_a_shorter_report() {
    // The second report is partial. Its tail must be zero even though the
    // same packet array was full on the first report.
    let apdu = [0xff; 60];
    let p = packets(&apdu);
    assert_eq!(p.len(), 2);
    assert_eq!(p[1][6..9], [0xff, 0xff, 0xff]);
    assert!(p[1][9..].iter().all(|&b| b == 0));
}

#[test]
fn channel_is_big_endian() {
    let mut out = Vec::new();
    packetize(0xbeef, &[1], |p| {
        out.push(*p);
        Ok(())
    })
    .unwrap();
    assert_eq!(out[0][1..3], [0xbe, 0xef]);
}

#[test]
fn sink_error_stops_after_the_failing_report() {
    let mut calls = 0;
    let result = packetize(LEDGER_CHANNEL, &[0; 200], |_| {
        calls += 1;
        Err(NativeTransportError::HidThreadUnavailable)
    });
    assert!(matches!(
        result,
        Err(NativeTransportError::HidThreadUnavailable)
    ));
    assert_eq!(calls, 1);
}

#[test]
fn every_apdu_length_round_trips_through_a_device() {
    for len in 0..=261usize {
        let apdu: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut device = MockDevice::default();
        packetize(LEDGER_CHANNEL, &apdu, |p| device.write(p)).unwrap();
        assert_eq!(device.received, vec![apdu], "length {len}");
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
    packetize(LEDGER_CHANNEL, cmd.as_bytes(), |p| device.write(p)).unwrap();
    assert_eq!(device.received, vec![cmd.as_bytes().to_vec()]);
}

#[test]
fn two_commands_in_sequence_both_reassemble() {
    let mut device = MockDevice::default();
    packetize(LEDGER_CHANNEL, &[1; 100], |p| device.write(p)).unwrap();
    packetize(LEDGER_CHANNEL, &[2; 3], |p| device.write(p)).unwrap();
    assert_eq!(device.received, vec![vec![1; 100], vec![2; 3]]);
}

// ---------------------------------------------------------------------------
// Read side

/// The reports the device sends for `response` on `channel`: the same framing
/// as the host side, without the leading report ID byte.
fn device_reports(channel: u16, response: &[u8]) -> Vec<ReadReport> {
    let mut out = Vec::new();
    packetize(channel, response, |p| {
        let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
        report.copy_from_slice(&p[1..]);
        out.push(report);
        Ok(())
    })
    .unwrap();
    out
}

/// A report source that hands out `reports` in order, each as a full read,
/// then panics.
fn source(
    reports: Vec<ReadReport>,
) -> impl FnMut(&mut ReadReport) -> Result<usize, NativeTransportError> {
    let mut reports = reports.into_iter();
    move |report| {
        *report = reports.next().expect("mock device has no more reports");
        Ok(report.len())
    }
}

#[test]
fn one_report_response_hand_built() {
    let mut report = [0u8; LEDGER_PACKET_READ_SIZE];
    report[..11].copy_from_slice(&[
        0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0x90, 0x00,
    ]);
    let answer = depacketize(LEDGER_CHANNEL, source(vec![report])).unwrap();
    assert_eq!(&*answer, &[0xde, 0xad, 0x90, 0x00]);
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

    let answer = depacketize(LEDGER_CHANNEL, source(vec![first, second])).unwrap();
    assert_eq!(&*answer, &response[..]);
}

#[test]
fn every_response_length_round_trips() {
    for len in 0..=ApduBuffer::CAPACITY {
        let response: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let reports = device_reports(LEDGER_CHANNEL, &response);
        let answer = depacketize(LEDGER_CHANNEL, source(reports)).unwrap();
        assert_eq!(&*answer, &response[..], "length {len}");
    }
}

#[test]
fn only_the_bytes_read_are_payload() {
    // Short reads: the report array still holds stale bytes past `n`.
    let first = device_reports(LEDGER_CHANNEL, &[7; 20]).remove(0);
    let mut calls = 0;
    let answer = depacketize(LEDGER_CHANNEL, |report| {
        calls += 1;
        report.fill(0xaa);
        if calls == 1 {
            // Header, length, and 3 payload bytes.
            report[..10].copy_from_slice(&first[..10]);
            Ok(10)
        } else {
            report[..5].copy_from_slice(&[0x01, 0x01, 0x05, 0x00, 0x01]);
            report[5..22].fill(7);
            Ok(22)
        }
    })
    .unwrap();
    assert_eq!(&*answer, &[7; 20]);
    assert_eq!(calls, 2);
}

#[test]
fn response_longer_than_a_short_apdu_is_rejected_before_reading_on() {
    let mut calls = 0;
    let err = depacketize(LEDGER_CHANNEL, |report| {
        calls += 1;
        report.fill(0);
        // Length 262.
        report[..7].copy_from_slice(&[0x01, 0x01, 0x05, 0x00, 0x00, 0x01, 0x06]);
        Ok(report.len())
    })
    .unwrap_err();
    assert!(matches!(err, NativeTransportError::ResponseTooLong(262)));
    assert_eq!(calls, 1);
}

#[test]
fn sequence_mismatch_is_detected() {
    let mut reports = device_reports(LEDGER_CHANNEL, &[1; 100]);
    reports[1][3..5].copy_from_slice(&[0, 2]);
    let err = depacketize(LEDGER_CHANNEL, source(reports)).unwrap_err();
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
    let err = depacketize(LEDGER_CHANNEL, source(reports)).unwrap_err();
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
    let err = depacketize(LEDGER_CHANNEL, source(reports)).unwrap_err();
    assert!(matches!(err, NativeTransportError::UnexpectedTag(0x06)));
}

#[test]
fn truncated_reports_are_errors() {
    let report = device_reports(LEDGER_CHANNEL, &[0x90, 0x00]).remove(0);
    for n in [0, 4, 6] {
        let err = depacketize(LEDGER_CHANNEL, |r| {
            *r = report;
            Ok(n)
        })
        .unwrap_err();
        assert!(matches!(err, NativeTransportError::TruncatedReport(got) if got == n));
    }

    // A continuation report with no payload must not spin forever.
    let reports = device_reports(LEDGER_CHANNEL, &[1; 100]);
    let mut calls = 0;
    let err = depacketize(LEDGER_CHANNEL, |r| {
        *r = reports[calls];
        calls += 1;
        Ok(if calls == 1 { r.len() } else { 5 })
    })
    .unwrap_err();
    assert!(matches!(err, NativeTransportError::EmptyReport));
    assert_eq!(calls, 2);
}

#[test]
fn source_errors_pass_through() {
    let err = depacketize(LEDGER_CHANNEL, |_| {
        Err(NativeTransportError::Timeout(Duration::from_secs(1)))
    })
    .unwrap_err();
    assert!(matches!(err, NativeTransportError::Timeout(d) if d == Duration::from_secs(1)));
}

#[test]
fn hid_timeouts() {
    assert_eq!(hid_timeout_ms(None), -1);
    assert_eq!(hid_timeout_ms(Some(Duration::ZERO)), 0);
    assert_eq!(hid_timeout_ms(Some(Duration::from_millis(1500))), 1500);
    assert_eq!(
        hid_timeout_ms(Some(Duration::from_micros(1))),
        1,
        "rounds up"
    );
    assert_eq!(
        hid_timeout_ms(Some(Duration::from_secs(u64::MAX))),
        i32::MAX
    );
}

#[test]
fn ledger_interface_filter() {
    assert!(is_ledger_interface(LEDGER_VID, LEDGER_USAGE_PAGE, 0));
    assert!(
        is_ledger_interface(LEDGER_VID, LEDGER_USAGE_PAGE, -1),
        "macOS reports no interface number"
    );
    assert!(!is_ledger_interface(0x1209, LEDGER_USAGE_PAGE, 0));
    assert!(
        !is_ledger_interface(LEDGER_VID, 0xF1D0, 1),
        "the FIDO interface is not the APDU interface"
    );
    assert_eq!(
        is_ledger_interface(LEDGER_VID, 0, 0),
        cfg!(target_os = "linux"),
        "interface 0 without a usage page is accepted only on Linux"
    );
}

// ---------------------------------------------------------------------------
// HID context thread

#[test]
fn hid_thread_is_one_named_thread_for_the_whole_process() {
    let id = || on_hid_thread(|| std::thread::current().id()).unwrap();
    let first = id();
    let again = std::thread::spawn(id).join().unwrap();
    assert_eq!(first, again, "every call runs on the same thread");
    assert_ne!(first, std::thread::current().id());
    let name = on_hid_thread(|| std::thread::current().name().map(str::to_owned)).unwrap();
    assert_eq!(name.as_deref(), Some("coins-ledger-hid"));
}

#[test]
fn hid_thread_returns_values_and_errors() {
    assert_eq!(on_hid_thread(|| 6 * 7).unwrap(), 42);
    let err = on_hid_thread(|| Err::<(), _>(NativeTransportError::DeviceNotFound))
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, NativeTransportError::DeviceNotFound));
}

#[test]
#[should_panic(expected = "boom")]
fn hid_thread_propagates_panics_to_the_caller() {
    let _ = on_hid_thread(|| panic!("boom"));
}

#[test]
fn hid_thread_runs_nested_calls_inline() {
    let value = on_hid_thread(|| on_hid_thread(|| 5).unwrap()).unwrap();
    assert_eq!(value, 5);
}

#[test]
fn hid_thread_survives_a_panicking_job() {
    let _ = std::panic::catch_unwind(|| on_hid_thread(|| panic!("first")));
    assert_eq!(
        on_hid_thread(|| 1).unwrap(),
        1,
        "the thread is still serving"
    );
}

// ---------------------------------------------------------------------------
// Device IDs

fn device_id(product_id: u16, serial: Option<&str>) -> HidDeviceId {
    HidDeviceId {
        path: c"/dev/hidraw3".to_owned(),
        product_id,
        serial_number: serial.map(str::to_owned),
        product_string: Some("Nano X".to_owned()),
    }
}

#[test]
fn device_id_display_is_model_and_serial() {
    assert_eq!(device_id(0x4011, Some("0001")).to_string(), "Nano X (0001)");
    assert_eq!(device_id(0x4011, None).to_string(), "Nano X");
    assert_eq!(device_id(0x8011, None).to_string(), "unknown model 0x8011");
}

#[test]
fn device_id_accessors() {
    let id = device_id(0x5011, Some("0001"));
    assert_eq!(id.model(), Model::NanoSPlus);
    assert_eq!(id.product_id(), 0x5011);
    assert_eq!(id.serial_number(), Some("0001"));
    assert_eq!(id.product_string(), Some("Nano X"));
    assert_eq!(id.path(), c"/dev/hidraw3");
}

// ---------------------------------------------------------------------------
// Hardware

/// hidapi's macOS backend binds its device manager to the run loop of the
/// thread that initialized it. A second thread must be able to open the
/// device while the first thread is still exiting, which is what a test
/// harness does between two tests. Run with `MallocScribble=1` on macOS to
/// make a regression deterministic.
#[test]
#[ignore = "needs a Ledger device"]
fn opening_while_the_previous_opener_thread_is_exiting() {
    let open = || {
        let transport = HidLedgerDevice::open_first().expect("a Ledger is attached");
        assert_eq!(
            transport.get_manufacturer_string().as_deref(),
            Some("Ledger")
        );
    };
    let (done, start) = std::sync::mpsc::channel();
    let first = std::thread::spawn(move || {
        open();
        done.send(()).unwrap();
    });
    let second = std::thread::spawn(move || {
        start.recv().unwrap();
        open();
    });
    first.join().unwrap();
    second.join().unwrap();
}

#[test]
#[ignore = "needs a Ledger device"]
fn every_listed_device_opens() {
    let ids = HidLedgerDevice::list().expect("enumeration works");
    assert!(!ids.is_empty(), "a Ledger is attached");
    for id in &ids {
        let device = HidLedgerDevice::open(id).expect("device opens");
        assert_eq!(device.get_manufacturer_string().as_deref(), Some("Ledger"));
    }
}
