use serial_test::serial;

use coins_ledger::{Ledger, common::*, transports::native::hid};

#[ignore]
#[test]
#[serial]
fn ledger_device_path() {
    let transport = hid::HidLedgerDevice::open_first().unwrap();

    let manufacturer = transport.get_manufacturer_string();
    println!("{manufacturer:?}");
}

#[ignore]
#[serial]
#[tokio::test]
async fn exchange() {
    let mut transport = Ledger::open_first_hid().expect("Could not get a device");
    // Ethereum `get_app_version`
    let command = CommandBuilder::new().cla(0xe0).ins(0x06).build().unwrap();
    let result = transport.exchange(command).await.unwrap();
    println!("{result}");
}
