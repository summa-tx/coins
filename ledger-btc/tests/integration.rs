use coins_core::ser::ByteFormat;
use coins_bip32::{
    enc::XKeyEncoder,
    path::KeyDerivation,
};
use bitcoins::types::{BitcoinTxIn, Script, ScriptPubkey, SpendScript, WitnessTx, UTXO};
use bitcoins_ledger::*;

use serial_test::serial;

#[tokio::test]
#[serial]
async fn it_retrieves_key_info() {
    let app = LedgerBTC::init().await.expect("No device");
    let result = app.get_xpub(&(vec![44u32, 44, 44, 44]).into()).await.unwrap();
    println!("{:?}", &result);
    println!(
        "{:?}",
        coins_bip32::MainnetEncoder::xpub_to_base58(&result.xpub).unwrap()
    );
}

#[tokio::test]
#[serial]
async fn it_doesnt_sign_without_the_key() {
    let app = LedgerBTC::init().await.expect("No device");

    let tx = WitnessTx::deserialize_hex("01000000000101f1e46af69e3ab97a3b195dbc34af1e2131ec31d53a6e331ab714504d27b6bd940400000000ffffffff03e0a57e000000000017a914e88869b88866281ab166541ad8aafba8f8aba47a8780841e00000000001976a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488aca31843a7380000002200201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc990400483045022100a74e04708f8032ce177c09642556945a5f5938de821edfa5df959c0ca61cb00d02207ea3b9353e0250a8a1440809a24a1d73c1c26d2c46e12dd96c7564ea4f8c6ee001473044022066611fd52c104f8be623cca6195ab0aa5dfc58408297744ff0d7b32da218c7d002200302be14cc76abaab271d848448d0b3cd3083d4dea76af495d1b1137d129d3120169522102489ec44d0358045c4be092978c40e574790820ebbc3bf069bffc12bda57af27d2102a4bf3a2bdbbcf2e68bbf04566052bbaf45dfe230a7a6de18d97c242fd85e9abc21038d4d2936c6e57f2093c2a43cb17fcf582afb1d312a1e129f900156075a490ae753ae00000000").unwrap();
    let prevout = UTXO::new(
        BitcoinTxIn::deserialize_hex("f1e46af69e3ab97a3b195dbc34af1e2131ec31d53a6e331ab714504d27b6bd940400000000ffffffff").unwrap().outpoint,
        243334728067,
        ScriptPubkey::deserialize_hex("220020b4d3e699f05e6a2c0d07b06d013508091d291098f9b68dac4a4d24844a2966df").unwrap(),
        SpendScript::Known(Script::deserialize_hex("69522102489ec44d0358045c4be092978c40e574790820ebbc3bf069bffc12bda57af27d2102a4bf3a2bdbbcf2e68bbf04566052bbaf45dfe230a7a6de18d97c242fd85e9abc21038d4d2936c6e57f2093c2a43cb17fcf582afb1d312a1e129f900156075a490ae753ae").unwrap()),
    );
    let deriv = KeyDerivation {
        root: [0u8; 4].into(),
        path: vec![44u32 + 2u32.pow(31), 2u32.pow(31), 2u32.pow(31), 0, 1].into(),
    };
    let info = SigningInfo {
        input_idx: 0,
        prevout: prevout,
        deriv: Some(deriv),
    };
    println!(
        "{:?}",
        app.get_tx_signatures(&tx, &[info]).await.unwrap()
    );
}


#[tokio::test]
#[serial]
async fn it_signs() {
    let app = LedgerBTC::init().await.expect("No device");
    let xpub = app.get_xpub(&(vec![]).into()).await.unwrap();

    let tx = WitnessTx::deserialize_hex("01000000000101f1e46af69e3ab97a3b195dbc34af1e2131ec31d53a6e331ab714504d27b6bd940400000000ffffffff03e0a57e000000000017a914e88869b88866281ab166541ad8aafba8f8aba47a8780841e00000000001976a9140e5c3c8d420c7f11e88d76f7b860d471e6517a4488aca31843a7380000002200201bf8a1831db5443b42a44f30a121d1b616d011ab15df62b588722a845864cc990400483045022100a74e04708f8032ce177c09642556945a5f5938de821edfa5df959c0ca61cb00d02207ea3b9353e0250a8a1440809a24a1d73c1c26d2c46e12dd96c7564ea4f8c6ee001473044022066611fd52c104f8be623cca6195ab0aa5dfc58408297744ff0d7b32da218c7d002200302be14cc76abaab271d848448d0b3cd3083d4dea76af495d1b1137d129d3120169522102489ec44d0358045c4be092978c40e574790820ebbc3bf069bffc12bda57af27d2102a4bf3a2bdbbcf2e68bbf04566052bbaf45dfe230a7a6de18d97c242fd85e9abc21038d4d2936c6e57f2093c2a43cb17fcf582afb1d312a1e129f900156075a490ae753ae00000000").unwrap();
    let prevout = UTXO::new(
        BitcoinTxIn::deserialize_hex("f1e46af69e3ab97a3b195dbc34af1e2131ec31d53a6e331ab714504d27b6bd940400000000ffffffff").unwrap().outpoint,
        243334728067,
        ScriptPubkey::deserialize_hex("220020b4d3e699f05e6a2c0d07b06d013508091d291098f9b68dac4a4d24844a2966df").unwrap(),
        SpendScript::Known(Script::deserialize_hex("69522102489ec44d0358045c4be092978c40e574790820ebbc3bf069bffc12bda57af27d2102a4bf3a2bdbbcf2e68bbf04566052bbaf45dfe230a7a6de18d97c242fd85e9abc21038d4d2936c6e57f2093c2a43cb17fcf582afb1d312a1e129f900156075a490ae753ae").unwrap()),
    );
    let deriv = KeyDerivation {
        root: xpub.derivation.root,
        path: vec![44u32 + 2u32.pow(31), 2u32.pow(31), 2u32.pow(31), 0, 1].into(),
    };
    let info = SigningInfo {
        input_idx: 0,
        prevout: prevout,
        deriv: Some(deriv),
    };
    println!("");
    println!("");
    println!("WAITING FOR CONFIRMATION");
    println!(
        "{:?}",
        app.get_tx_signatures(&tx, &[info]).await.unwrap()
    );
}
