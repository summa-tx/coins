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
