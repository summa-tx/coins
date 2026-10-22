//! AI-written integration tests against a real Speculos running Ledger's
//! [app-boilerplate](https://github.com/LedgerHQ/app-boilerplate) 2.3.2. A
//! submodule of `src/transports/speculos/mod.rs`.
//!
//! They run only when `SPECULOS_APDU_ADDR` is set, and then also need
//! `SPECULOS_API_URL` and `SPECULOS_MODEL` (`nanox`, `nanosp`, `stax` or
//! `flex`). See the crate README for how to start Speculos.
//!
//! The approval scenarios ask the app to show an address for confirmation
//! (`GET_PUBLIC_KEY` with P1=1). Every test leaves the app on its home screen.

use std::time::Duration;

use futures_util::StreamExt;
use tokio::time::{Instant, sleep, timeout};

use super::*;
use crate::{
    CommandBuilder, Ledger, LedgerError, Model,
    common::{ApduAnswer, ApduCommand, StatusWord},
    transports::LedgerTransport,
};

const CLA: u8 = 0xe0;
const INS_GET_APP_NAME: u8 = 0x04;
const INS_GET_PUBLIC_KEY: u8 = 0x05;
/// `GET_PUBLIC_KEY` P1 that shows the address for approval.
const P1_CONFIRM: u8 = 0x01;
/// Length of an uncompressed secp256k1 public key, the reply's first byte.
const PUBKEY_LEN: u8 = 65;

/// The home screen's title. Matched exactly: other screens contain it.
const HOME: &str = "Boilerplate";
/// The first screen of the address prompt.
const PROMPT: &str = "Verify BOL address";
/// The title of the screen showing the address.
const ADDRESS_TITLE: &str = "Address";
const CONFIRM: &str = "Confirm";
const CANCEL: &str = "Cancel";

/// Navigation steps before giving up on finding a target.
const MAX_STEPS: usize = 15;
/// Bound on one screen transition or one prompt appearing.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on exchanges that wait for an approval.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often to poll the current screen.
const POLL: Duration = Duration::from_millis(100);

const TAP: Action = Action::PressAndRelease { delay: None };

/// The Speculos under test, or `None` to skip.
fn speculos() -> Option<(String, SpeculosClient, Model)> {
    let Ok(addr) = std::env::var("SPECULOS_APDU_ADDR") else {
        eprintln!("SPECULOS_APDU_ADDR is unset; skipping Speculos integration test");
        return None;
    };
    let url = std::env::var("SPECULOS_API_URL")
        .expect("SPECULOS_API_URL must be set when SPECULOS_APDU_ADDR is");
    let model = std::env::var("SPECULOS_MODEL")
        .expect("SPECULOS_MODEL must be set when SPECULOS_APDU_ADDR is");
    let model = match model.as_str() {
        "nanox" => Model::NanoX,
        "nanosp" => Model::NanoSPlus,
        "stax" => Model::Stax,
        "flex" => Model::Flex,
        other => panic!("unsupported SPECULOS_MODEL {other:?}"),
    };
    let client = SpeculosClient::new(url).expect("SPECULOS_API_URL is a URL");
    Some((addr, client, model))
}

async fn connect(addr: &str, model: Model) -> SpeculosTransport {
    timeout(STEP_TIMEOUT, SpeculosTransport::connect(addr, model))
        .await
        .expect("connecting to Speculos timed out")
        .expect("Speculos APDU port is reachable")
}

fn app_name_cmd() -> ApduCommand {
    CommandBuilder::new()
        .cla(CLA)
        .ins(INS_GET_APP_NAME)
        .build()
        .unwrap()
}

/// `GET_PUBLIC_KEY` for `m/44'/1'/0'/0/0`, shown for approval.
fn address_cmd() -> ApduCommand {
    const HARD: u32 = 0x8000_0000;
    let path = [44 | HARD, 1 | HARD, HARD, 0, 0];
    let mut data = vec![path.len() as u8];
    for component in path {
        data.extend_from_slice(&component.to_be_bytes());
    }
    CommandBuilder::new()
        .cla(CLA)
        .ins(INS_GET_PUBLIC_KEY)
        .p1(P1_CONFIRM)
        .data(&data)
        .build()
        .unwrap()
}

/// Where the next-page arrow sits on a touch model, or `None` for a button
/// model. Read off screenshots of the boilerplate prompt.
const fn next_page(model: Model) -> Option<(u16, u16)> {
    match model {
        Model::Flex => Some((430, 550)),
        Model::Stax => Some((360, 626)),
        _ => None,
    }
}

/// Poll the current screen until it is non-empty, differs from `prev`, and
/// is unchanged across two reads, so a half-drawn screen is never acted on.
async fn settled_screen(client: &SpeculosClient, prev: &[ScreenEvent]) -> Vec<ScreenEvent> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    let mut last = client.current_screen().await.unwrap();
    loop {
        assert!(
            Instant::now() < deadline,
            "screen did not settle on a new page; last saw {last:?}"
        );
        sleep(POLL).await;
        let now = client.current_screen().await.unwrap();
        if now == last && !now.is_empty() && now != prev {
            return now;
        }
        last = now;
    }
}

/// Wait for the address prompt, page forward until a screen shows `target`,
/// and select it: both buttons on a button model, a tap on its text on a
/// touch model.
async fn choose(client: &SpeculosClient, model: Model, target: &str) {
    client
        .wait_for_text(PROMPT, STEP_TIMEOUT)
        .await
        .expect("the address prompt appears");
    let mut screen = settled_screen(client, &[]).await;
    for _ in 0..MAX_STEPS {
        if let Some(ev) = screen.iter().find(|e| e.text == target) {
            match next_page(model) {
                None => client.button(Button::Both, TAP).await.unwrap(),
                Some(_) => {
                    let x = u16::try_from(ev.x).unwrap();
                    let y = u16::try_from(ev.y).unwrap();
                    client.finger(x, y, TAP).await.unwrap();
                }
            }
            return;
        }
        match next_page(model) {
            None => client.button(Button::Right, TAP).await.unwrap(),
            Some((x, y)) => client.finger(x, y, TAP).await.unwrap(),
        }
        screen = settled_screen(client, &screen).await;
    }
    panic!("{target:?} not found within {MAX_STEPS} pages; last saw {screen:?}");
}

async fn approve(client: &SpeculosClient, model: Model) {
    choose(client, model, CONFIRM).await;
}

async fn reject(client: &SpeculosClient, model: Model) {
    choose(client, model, CANCEL).await;
}

/// Wait until the app is back on its home screen.
async fn wait_home(client: &SpeculosClient) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    loop {
        let screen = client.current_screen().await.unwrap();
        if screen.iter().any(|e| e.text == HOME) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "app did not return home; screen is {screen:?}"
        );
        sleep(POLL).await;
    }
}

/// Send the address command and resolve its prompt with `nav`.
async fn address_flow<F>(
    transport: &mut SpeculosTransport,
    client: &SpeculosClient,
    nav: F,
) -> Result<ApduAnswer, LedgerError>
where
    F: Future<Output = ()>,
{
    client.clear_events().await.unwrap();
    let (answer, ()) = tokio::join!(
        transport.exchange(address_cmd(), Some(EXCHANGE_TIMEOUT)),
        nav
    );
    answer
}

#[tokio::test]
#[serial_test::serial]
async fn app_name() {
    let Some((addr, _client, model)) = speculos() else {
        return;
    };
    let mut ledger = Ledger::connect_speculos(addr.as_str(), model)
        .await
        .expect("Speculos APDU port is reachable");
    ledger.set_timeout(Some(STEP_TIMEOUT));
    let answer = ledger.exchange(app_name_cmd()).await.unwrap();
    assert_eq!(answer.data(), b"Boilerplate");
}

#[tokio::test]
#[serial_test::serial]
async fn approve_address() {
    let Some((addr, client, model)) = speculos() else {
        return;
    };
    let mut transport = connect(&addr, model).await;
    let answer = address_flow(&mut transport, &client, approve(&client, model))
        .await
        .unwrap();
    assert_eq!(answer.data().first(), Some(&PUBKEY_LEN));
    wait_home(&client).await;
}

#[tokio::test]
#[serial_test::serial]
async fn reject_address() {
    let Some((addr, client, model)) = speculos() else {
        return;
    };
    let mut transport = connect(&addr, model).await;
    let err = address_flow(&mut transport, &client, reject(&client, model))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LedgerError::BadRetcode(StatusWord::CONDITIONS_NOT_SATISFIED)
        ),
        "{err:?}"
    );
    wait_home(&client).await;
}

#[tokio::test]
#[serial_test::serial]
async fn timeout_then_recover() {
    let Some((addr, client, model)) = speculos() else {
        return;
    };
    let mut transport = connect(&addr, model).await;
    client.clear_events().await.unwrap();

    let t = Duration::from_millis(500);
    let err = transport
        .exchange(address_cmd(), Some(t))
        .await
        .unwrap_err();
    assert!(matches!(err, LedgerError::Timeout(d) if d == t), "{err:?}");

    let err = transport
        .exchange(app_name_cmd(), Some(STEP_TIMEOUT))
        .await
        .unwrap_err();
    let LedgerError::Transport(inner) = err else {
        panic!("expected a transport error, got {err:?}");
    };
    assert!(
        matches!(
            inner.downcast_ref::<SpeculosError>(),
            Some(SpeculosError::PendingReply)
        ),
        "{inner:?}"
    );

    reject(&client, model).await;
    transport
        .discard_pending(Duration::from_secs(5))
        .await
        .unwrap();

    let answer = transport
        .exchange(app_name_cmd(), Some(STEP_TIMEOUT))
        .await
        .unwrap();
    assert_eq!(answer.data(), b"Boilerplate");
    wait_home(&client).await;
}

#[tokio::test]
#[serial_test::serial]
async fn event_stream_sees_address_screen() {
    let Some((addr, client, model)) = speculos() else {
        return;
    };
    let mut transport = connect(&addr, model).await;
    client.clear_events().await.unwrap();
    let mut stream = std::pin::pin!(client.event_stream().await.unwrap());

    address_flow(&mut transport, &client, approve(&client, model))
        .await
        .unwrap();

    let seen = timeout(STEP_TIMEOUT, async {
        while let Some(ev) = stream.next().await {
            if ev.unwrap().text == ADDRESS_TITLE {
                return true;
            }
        }
        false
    })
    .await
    .expect("the address screen reached the stream in time");
    assert!(seen, "the stream ended without the address screen");
    wait_home(&client).await;
}
