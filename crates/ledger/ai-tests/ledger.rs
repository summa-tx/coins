//! AI-written tests for `Ledger` over a mock transport. A submodule of
//! `src/ledger.rs`.

use super::*;
use crate::{
    common::{CommandBuilder, StatusWord},
    transports::ai_tests::{MockTransport, ScriptExhausted},
};

fn get_version() -> ApduCommand {
    CommandBuilder::new().cla(0xe0).ins(0x06).build().unwrap()
}

#[tokio::test]
async fn success_reply_returns_its_data() {
    let mut mock = MockTransport::new().reply(&[1, 2, 3]);
    let mut ledger = Ledger::from_transport(&mut mock);
    let answer = ledger.exchange(get_version()).await.unwrap();
    assert_eq!(answer.data(), &[1, 2, 3]);
    assert_eq!(answer.status(), StatusWord::SUCCESS);
    assert_eq!(mock.sent, vec![get_version()]);
}

#[tokio::test]
async fn non_success_status_is_an_error() {
    let mut mock = MockTransport::new().reply_with(&[], StatusWord::CONDITIONS_NOT_SATISFIED);
    let mut ledger = Ledger::from_transport(&mut mock);
    let err = ledger.exchange(get_version()).await.unwrap_err();
    assert!(matches!(
        err,
        LedgerError::BadRetcode(StatusWord::CONDITIONS_NOT_SATISFIED)
    ));
}

#[tokio::test]
async fn unknown_status_is_an_error_not_an_empty_answer() {
    // Codes outside the old closed enum used to come back as Ok with no data.
    let mut mock = MockTransport::new().reply_with(&[], StatusWord::new(0x6e01));
    let mut ledger = Ledger::from_transport(&mut mock);
    let err = ledger.exchange(get_version()).await.unwrap_err();
    assert!(matches!(err, LedgerError::BadRetcode(sw) if sw.raw() == 0x6e01));
}

#[tokio::test]
async fn locked_device_is_reported_as_such() {
    let mut mock = MockTransport::new().reply_with(&[], StatusWord::LOCKED_DEVICE);
    let mut ledger = Ledger::from_transport(&mut mock);
    let err = ledger.exchange(get_version()).await.unwrap_err();
    assert!(matches!(
        err,
        LedgerError::BadRetcode(StatusWord::LOCKED_DEVICE)
    ));
    assert!(err.to_string().contains("Device locked"));
}

#[tokio::test]
async fn transport_timeouts_pass_through() {
    let timeout = Duration::from_secs(1);
    let mut mock = MockTransport::new().fail(LedgerError::Timeout(timeout));
    let mut ledger = Ledger::from_transport(&mut mock);
    assert!(matches!(
        ledger.exchange(get_version()).await,
        Err(LedgerError::Timeout(d)) if d == timeout
    ));
}

#[tokio::test]
async fn timeout_is_forwarded_and_settable() {
    let mut mock = MockTransport::new().reply(&[]).reply(&[]);
    let mut ledger = Ledger::from_transport(&mut mock);
    assert_eq!(ledger.timeout(), None);
    ledger.exchange(get_version()).await.unwrap();

    let short = Some(Duration::from_millis(250));
    ledger.set_timeout(short);
    assert_eq!(ledger.timeout(), short);
    ledger.exchange(get_version()).await.unwrap();

    assert_eq!(mock.timeouts, vec![None, short]);
}

#[tokio::test]
async fn commands_arrive_in_order_and_unchanged() {
    let cmds = [
        get_version(),
        CommandBuilder::new()
            .cla(0xe0)
            .ins(0x02)
            .p2(1)
            .data(&[9; 20])
            .build()
            .unwrap(),
        CommandBuilder::new()
            .cla(0xe0)
            .ins(0x04)
            .p1(0x80)
            .data(&[0; 255])
            .le(7)
            .build()
            .unwrap(),
    ];
    let mut mock = MockTransport::new().reply(&[]).reply(&[]).reply(&[]);
    let mut ledger = Ledger::from_transport(&mut mock);
    for cmd in cmds {
        ledger.exchange(cmd).await.unwrap();
    }
    assert_eq!(mock.sent, cmds);
}

#[tokio::test]
async fn chunked_payload_is_delivered_whole() {
    // The signer pattern: one builder, p1 marks first vs continuation, and
    // the answer from each round can be held while the next is sent.
    let payload: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
    let chunks: Vec<&[u8]> = payload.chunks(255).collect();

    let mut mock = MockTransport::new();
    for _ in 1..chunks.len() {
        mock = mock.reply(&[]);
    }
    mock = mock.reply(&[0xab; 65]);

    let base = CommandBuilder::new().cla(0xe0).ins(0x04);
    let mut ledger = Ledger::from_transport(&mut mock);
    let mut last = None;
    for (i, chunk) in chunks.iter().enumerate() {
        let p1 = if i == 0 { 0x00 } else { 0x80 };
        let cmd = base.p1(p1).data(chunk).build().unwrap();
        last = Some(ledger.exchange(cmd).await.unwrap());
    }

    assert_eq!(last.unwrap().data(), &[0xab; 65]);
    assert_eq!(mock.sent.len(), 3);
    assert_eq!(mock.sent[0].p1(), 0x00);
    assert!(mock.sent[1..].iter().all(|c| c.p1() == 0x80));
    let delivered: Vec<u8> = mock.sent.iter().flat_map(|c| c.data().to_vec()).collect();
    assert_eq!(delivered, payload);
}

#[tokio::test]
async fn transport_errors_pass_through_and_downcast() {
    let mut mock = MockTransport::new();
    let mut ledger = Ledger::from_transport(&mut mock);
    let err = ledger.exchange(get_version()).await.unwrap_err();
    let LedgerError::Transport(inner) = err else {
        panic!("expected Transport, got {err:?}");
    };
    assert!(inner.downcast_ref::<ScriptExhausted>().is_some());
}

#[cfg(feature = "speculos")]
#[tokio::test]
async fn connect_speculos_reports_model() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ledger = Ledger::connect_speculos(addr, crate::Model::Flex)
        .await
        .unwrap();
    assert_eq!(
        ledger.identity(),
        Some(DeviceIdentity::new(crate::Model::Flex, None))
    );
}

/// After a timed-out exchange, the caller recovers through
/// `Ledger::transport_mut`.
#[cfg(feature = "speculos")]
#[tokio::test]
async fn speculos_recovers_after_timeout_via_transport_mut() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    async fn read_frame(server: &mut TcpStream) {
        let mut len = [0u8; 4];
        server.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        server.read_exact(&mut body).await.unwrap();
    }

    async fn write_reply(server: &mut TcpStream, data: &[u8]) {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out.extend_from_slice(&0x9000u16.to_be_bytes());
        server.write_all(&out).await.unwrap();
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (ledger, accepted) = tokio::join!(
        Ledger::connect_speculos(addr, crate::Model::NanoSPlus),
        listener.accept()
    );
    let mut ledger = ledger.unwrap();
    let mut server = accepted.unwrap().0;
    ledger.set_timeout(Some(Duration::from_millis(100)));

    // The first exchange times out: the server reads the command and stalls.
    let (res, ()) = tokio::join!(ledger.exchange(get_version()), read_frame(&mut server));
    assert!(matches!(res.unwrap_err(), LedgerError::Timeout(_)));

    // Further exchanges are refused while the reply is pending.
    let err = ledger.exchange(get_version()).await.unwrap_err();
    let LedgerError::Transport(inner) = err else {
        panic!("expected Transport, got {err:?}");
    };
    assert!(matches!(
        inner.downcast_ref::<SpeculosError>(),
        Some(SpeculosError::PendingReply)
    ));

    // The late reply arrives, and is discarded.
    write_reply(&mut server, &[9]).await;
    ledger
        .transport_mut()
        .discard_pending(Duration::from_secs(1))
        .await
        .unwrap();

    // The connection works again.
    ledger.set_timeout(Some(Duration::from_secs(5)));
    let srv = async {
        read_frame(&mut server).await;
        write_reply(&mut server, &[1, 2]).await;
    };
    let (answer, ()) = tokio::join!(ledger.exchange(get_version()), srv);
    assert_eq!(answer.unwrap().data(), &[1, 2]);
}
