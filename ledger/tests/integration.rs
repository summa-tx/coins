use serial_test::serial;

use rmn_ledger::{
    common::*,
    transports::{self, hid, LedgerSync},
};

// // TODO: refactor or delete this
// #[test]
// #[serial]
// fn list_all_devices() {
//     let apiwrapper = hid::HIDAPIWRAPPER.lock().expect("Could not lock api wrapper");
//     let api_mutex = apiwrapper.get().expect("Error getting api_mutex");
//     let api = api_mutex.lock().expect("Could not lock");
//
//     for device_info in api.device_list() {
//         println!(
//             "{:#?} - {:#x}/{:#x}/{:#x}/{:#x} {:#} {:#}",
//             device_info.path(),
//             device_info.vendor_id(),
//             device_info.product_id(),
//             device_info.usage_page(),
//             device_info.interface_number(),
//             device_info.manufacturer_string().clone().unwrap_or_default(),
//             device_info.product_string().clone().unwrap_or_default()
//         );
//     }
// }

#[test]
#[serial]
fn ledger_device_path() {
    let transport = hid::TransportNativeHID::new().unwrap();

    // TODO: Extend to discover two devices
    let ledger_path = transport.device_path().expect("Could not find a device");
    println!("{:?}", ledger_path);
}

#[test]
#[serial]
fn exchange() {
    let transport = transports::Ledger::init().expect("Could not get a device");
    let buf: &[u8] = &[];
    // Ethereum `get_app_version`
    let command = APDUCommand {
        ins: 0x06,
        p1: 0x00,
        p2: 0x00,
        data: buf.into(),
        response_len: None,
    };
    let result = transport.exchange(&command).unwrap();
    println!("{}", result);
}
