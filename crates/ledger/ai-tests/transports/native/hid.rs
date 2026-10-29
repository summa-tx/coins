//! AI-written tests for Ledger discovery over HID. A submodule of
//! `src/transports/native/hid.rs`.

use super::*;

#[test]
fn ledger_interface_filter() {
    assert!(HidDeviceId::is_ledger_interface(
        LEDGER_VID,
        LEDGER_USAGE_PAGE,
        0
    ));
    assert!(
        HidDeviceId::is_ledger_interface(LEDGER_VID, LEDGER_USAGE_PAGE, -1),
        "macOS reports no interface number"
    );
    assert!(!HidDeviceId::is_ledger_interface(
        0x1209,
        LEDGER_USAGE_PAGE,
        0
    ));
    assert!(
        !HidDeviceId::is_ledger_interface(LEDGER_VID, 0xF1D0, 1),
        "the FIDO interface is not the APDU interface"
    );
    assert_eq!(
        HidDeviceId::is_ledger_interface(LEDGER_VID, 0, 0),
        cfg!(target_os = "linux"),
        "interface 0 without a usage page is accepted only on Linux"
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
