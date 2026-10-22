//! AI-written tests for `SpeculosTransport`. A submodule of
//! `src/transports/speculos/transport.rs`. A local `TcpListener` plays
//! Speculos.

use tokio::net::TcpListener;

use super::*;
use crate::{CommandBuilder, common::StatusWord};

async fn fake() -> (SpeculosTransport, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (t, accepted) = tokio::join!(
        SpeculosTransport::connect(addr, Model::NanoSPlus),
        listener.accept()
    );
    (t.unwrap(), accepted.unwrap().0)
}

async fn read_frame(server: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    server.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    server.read_exact(&mut body).await.unwrap();
    body
}

async fn write_reply(server: &mut TcpStream, data: &[u8], sw: u16) {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out.extend_from_slice(&sw.to_be_bytes());
    server.write_all(&out).await.unwrap();
}

fn speculos_err(e: LedgerError) -> SpeculosError {
    match e {
        LedgerError::Transport(e) => *e.downcast::<SpeculosError>().unwrap(),
        other => panic!("not a transport error: {other:?}"),
    }
}

fn cmd() -> ApduCommand {
    CommandBuilder::new().cla(0xe0).ins(0x03).build().unwrap()
}

#[tokio::test]
async fn round_trip() {
    let (mut t, mut server) = fake().await;
    let cmd = cmd();
    let srv = async {
        assert_eq!(read_frame(&mut server).await, cmd.as_bytes());
        write_reply(&mut server, &[1, 2, 3], 0x9000).await;
    };
    let (ans, ()) = tokio::join!(t.exchange(cmd, None), srv);
    let ans = ans.unwrap();
    assert_eq!(ans.data(), &[1, 2, 3]);
    assert_eq!(ans.status(), StatusWord::SUCCESS);
}

#[tokio::test]
async fn sw_only_reply() {
    let (mut t, mut server) = fake().await;
    let srv = async {
        read_frame(&mut server).await;
        write_reply(&mut server, &[], 0x9000).await;
    };
    let (ans, ()) = tokio::join!(t.exchange(cmd(), None), srv);
    let ans = ans.unwrap();
    assert!(ans.data().is_empty());
    assert_eq!(ans.status(), StatusWord::SUCCESS);
}

#[tokio::test]
async fn bad_status_does_not_poison() {
    let (mut t, mut server) = fake().await;
    let srv = async {
        read_frame(&mut server).await;
        write_reply(&mut server, &[], 0x6985).await;
        read_frame(&mut server).await;
        write_reply(&mut server, &[7], 0x9000).await;
    };
    let client = async {
        let err = t.exchange(cmd(), None).await.unwrap_err();
        assert!(matches!(
            err,
            LedgerError::BadRetcode(StatusWord::CONDITIONS_NOT_SATISFIED)
        ));
        t.exchange(cmd(), None).await.unwrap()
    };
    let (ans, ()) = tokio::join!(client, srv);
    assert_eq!(ans.data(), &[7]);
}

#[tokio::test]
async fn too_long_reply_breaks() {
    let (mut t, mut server) = fake().await;
    let srv = async {
        read_frame(&mut server).await;
        server.write_all(&260u32.to_be_bytes()).await.unwrap();
    };
    let (res, ()) = tokio::join!(t.exchange(cmd(), None), srv);
    assert!(matches!(
        speculos_err(res.unwrap_err()),
        SpeculosError::ResponseTooLong(262)
    ));
    let err = t.exchange(cmd(), None).await.unwrap_err();
    assert!(matches!(speculos_err(err), SpeculosError::Broken));
}

#[tokio::test]
async fn identity_is_configured_model() {
    let (t, _server) = fake().await;
    assert_eq!(
        t.identity(),
        Some(DeviceIdentity::new(Model::NanoSPlus, None))
    );
}

const SHORT: Duration = Duration::from_millis(50);
const LONG: Duration = Duration::from_secs(1);

/// `exchange(cmd(), Some(SHORT))`, failing rather than hanging if the transport
/// ignores the timeout.
async fn exchange_short(t: &mut SpeculosTransport) -> Result<ApduAnswer, LedgerError> {
    tokio::time::timeout(LONG, t.exchange(cmd(), Some(SHORT)))
        .await
        .expect("the transport ignored its timeout")
}

/// Send `cmd()` and let the server consume it without replying, so the
/// exchange times out.
async fn time_out(t: &mut SpeculosTransport, server: &mut TcpStream) {
    let (res, _) = tokio::join!(exchange_short(t), read_frame(server));
    assert!(matches!(res.unwrap_err(), LedgerError::Timeout(d) if d == SHORT));
}

/// Exchange `cmd()` with the server replying `[7]`.
async fn round_trip_seven(t: &mut SpeculosTransport, server: &mut TcpStream) {
    let srv = async {
        read_frame(server).await;
        write_reply(server, &[7], 0x9000).await;
    };
    let (ans, ()) = tokio::join!(tokio::time::timeout(LONG, t.exchange(cmd(), None)), srv);
    assert_eq!(ans.unwrap().unwrap().data(), &[7]);
}

/// The next exchange fails with `PendingReply` without writing a command.
async fn assert_pending(t: &mut SpeculosTransport) {
    let err = tokio::time::timeout(LONG, t.exchange(cmd(), None))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(speculos_err(err), SpeculosError::PendingReply));
}

#[tokio::test]
async fn timeout_poisons() {
    let (mut t, mut server) = fake().await;
    time_out(&mut t, &mut server).await;
    assert_pending(&mut t).await;
}

#[tokio::test]
async fn dropped_exchange_poisons() {
    let (mut t, mut server) = fake().await;
    let (res, _) = tokio::join!(
        tokio::time::timeout(SHORT, t.exchange(cmd(), None)),
        read_frame(&mut server)
    );
    assert!(res.is_err(), "the exchange should have been dropped");
    assert_pending(&mut t).await;
}

#[tokio::test]
async fn discard_pending_recovers() {
    let (mut t, mut server) = fake().await;
    time_out(&mut t, &mut server).await;
    write_reply(&mut server, &[], 0x9000).await;
    t.discard_pending(LONG).await.unwrap();
    round_trip_seven(&mut t, &mut server).await;
}

#[tokio::test]
async fn timeout_mid_frame_then_discard() {
    let (mut t, mut server) = fake().await;
    let srv = async {
        read_frame(&mut server).await;
        server.write_all(&[0, 0, 0, 3, 0xaa]).await.unwrap();
    };
    let (res, ()) = tokio::join!(exchange_short(&mut t), srv);
    assert!(matches!(res.unwrap_err(), LedgerError::Timeout(d) if d == SHORT));
    server.write_all(&[0xbb, 0xcc, 0x90, 0x00]).await.unwrap();
    t.discard_pending(LONG).await.unwrap();
    round_trip_seven(&mut t, &mut server).await;
}

#[tokio::test]
async fn discard_pending_times_out() {
    let (mut t, mut server) = fake().await;
    time_out(&mut t, &mut server).await;
    assert!(matches!(
        t.discard_pending(SHORT).await,
        Err(SpeculosError::NoReply(d)) if d == SHORT
    ));
    assert_pending(&mut t).await;
}

#[tokio::test]
async fn discard_pending_when_ready_is_noop() {
    let (mut t, _server) = fake().await;
    t.discard_pending(SHORT).await.unwrap();
}

#[tokio::test]
async fn eof_mid_reply_breaks() {
    let (mut t, mut server) = fake().await;
    let srv = async move {
        read_frame(&mut server).await;
        server.write_all(&3u32.to_be_bytes()).await.unwrap();
    };
    let (res, ()) = tokio::join!(t.exchange(cmd(), Some(LONG)), srv);
    assert!(matches!(
        speculos_err(res.unwrap_err()),
        SpeculosError::Io(_)
    ));
    let err = t.exchange(cmd(), None).await.unwrap_err();
    assert!(matches!(speculos_err(err), SpeculosError::Broken));
    assert!(matches!(
        t.discard_pending(LONG).await,
        Err(SpeculosError::Broken)
    ));
}

#[tokio::test]
async fn max_length_header_is_too_long() {
    let (mut t, mut server) = fake().await;
    let srv = async {
        read_frame(&mut server).await;
        server.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    };
    let (res, ()) = tokio::join!(t.exchange(cmd(), None), srv);
    assert!(matches!(
        speculos_err(res.unwrap_err()),
        SpeculosError::ResponseTooLong(_)
    ));
}
