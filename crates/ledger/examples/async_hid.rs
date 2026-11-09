//! Ask a Ledger which app is running, and its version, over async HID.
//!
//! Plug in and unlock a Ledger, then run:
//!
//! ```sh
//! cargo run -p coins-ledger --example async_hid
//! ```

use std::time::Duration;

use coins_ledger::{CommandBuilder, Ledger};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enumerate attached Ledgers. Empty under Termux.
    for id in Ledger::list_hid()? {
        println!("found {id}");
    }

    // Take the first one.
    let mut ledger = Ledger::open_first_hid()?.with_timeout(Some(Duration::from_secs(10)));
    if let Some(identity) = ledger.identity() {
        println!("opened {identity}");
    }

    // GET_APP_AND_VERSION. The dashboard and every app answer it.
    let command = CommandBuilder::new().cla(0xb0).ins(0x01).build()?;

    // I/O runs on a background thread. Up to 10s per report.
    let answer = ledger.exchange(command).await?;

    // Reply: format 1, then length-prefixed name and version.
    let [1, rest @ ..] = answer.data() else {
        return Err("unknown reply format".into());
    };
    let (name, rest) = field(rest).ok_or("malformed name")?;
    let (version, _) = field(rest).ok_or("malformed version")?;
    // "BOLOS" is the dashboard.
    println!("{name} {version}");

    // Dropping the ledger closes the device.
    Ok(())
}

/// Split one length-prefixed UTF-8 field off the front of `bytes`.
fn field(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    let (field, rest) = rest.split_at_checked(len.into())?;
    Some((std::str::from_utf8(field).ok()?, rest))
}
