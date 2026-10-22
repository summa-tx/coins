//! AI-written tests for `SpeculosClient`. A submodule of
//! `src/transports/speculos/client.rs`. A local `TcpListener` plays the
//! Speculos HTTP API.

use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::*;

type Canned = (u16, &'static str, Vec<u8>);

const WAIT: Duration = Duration::from_secs(10);

/// Read one full HTTP request (head and Content-Length body) as a string.
async fn read_request(sock: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = sock.read(&mut chunk).await.unwrap();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse::<usize>().unwrap());
            if buf.len() >= pos + 4 + len {
                break;
            }
        }
        if n == 0 {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

async fn serve(responses: Vec<Canned>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let mut seen = Vec::new();
        for (status, ctype, body) in responses {
            let (mut sock, _) = listener.accept().await.unwrap();
            seen.push(read_request(&mut sock).await);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(&body).await.unwrap();
            let _ = sock.shutdown().await;
        }
        seen
    });
    (url, handle)
}

fn body_json(req: &str) -> serde_json::Value {
    let body = req.split("\r\n\r\n").nth(1).unwrap();
    serde_json::from_str(body).unwrap()
}

fn request_line(req: &str) -> &str {
    req.lines().next().unwrap()
}

fn events_body(texts: &[&str]) -> Vec<u8> {
    let evs: Vec<_> = texts
        .iter()
        .map(|t| serde_json::json!({"text": t, "x": 1, "y": 2}))
        .collect();
    serde_json::to_vec(&serde_json::json!({ "events": evs })).unwrap()
}

#[tokio::test]
async fn button_posts_action() {
    let (url, seen) = serve(vec![(200, "text/plain", vec![])]).await;
    let client = SpeculosClient::new(url).unwrap();
    client
        .button(Button::Right, Action::PressAndRelease { delay: None })
        .await
        .unwrap();
    let req = &seen.await.unwrap()[0];
    assert_eq!(request_line(req), "POST /button/right HTTP/1.1");
    assert_eq!(
        body_json(req),
        serde_json::json!({"action": "press-and-release"})
    );
}

#[tokio::test]
async fn delay_is_seconds() {
    let (url, seen) = serve(vec![(200, "text/plain", vec![])]).await;
    let client = SpeculosClient::new(url).unwrap();
    let action = Action::PressAndRelease {
        delay: Some(Duration::from_millis(250)),
    };
    client.button(Button::Both, action).await.unwrap();
    let req = &seen.await.unwrap()[0];
    assert_eq!(request_line(req), "POST /button/both HTTP/1.1");
    assert_eq!(
        body_json(req),
        serde_json::json!({"action": "press-and-release", "delay": 0.25})
    );
}

#[tokio::test]
async fn finger_posts_coords() {
    let (url, seen) = serve(vec![(200, "text/plain", vec![])]).await;
    let client = SpeculosClient::new(url).unwrap();
    client.finger(10, 20, Action::Press).await.unwrap();
    let req = &seen.await.unwrap()[0];
    assert_eq!(request_line(req), "POST /finger HTTP/1.1");
    assert_eq!(
        body_json(req),
        serde_json::json!({"action": "press", "x": 10, "y": 20})
    );
}

#[tokio::test]
async fn events_parse() {
    let body = br#"{"events":[{"text":"Boilerplate","x":1,"y":2}]}"#.to_vec();
    let (url, seen) = serve(vec![
        (200, "application/json", body.clone()),
        (200, "application/json", body),
    ])
    .await;
    let client = SpeculosClient::new(url).unwrap();
    let expected = vec![ScreenEvent {
        text: "Boilerplate".into(),
        x: 1,
        y: 2,
    }];
    assert_eq!(client.events().await.unwrap(), expected);
    assert_eq!(client.current_screen().await.unwrap(), expected);
    let seen = seen.await.unwrap();
    assert_eq!(request_line(&seen[0]), "GET /events HTTP/1.1");
    assert_eq!(
        request_line(&seen[1]),
        "GET /events?currentscreenonly=true HTTP/1.1"
    );
}

#[tokio::test]
async fn clear_events_deletes() {
    let (url, seen) = serve(vec![(200, "text/plain", vec![])]).await;
    SpeculosClient::new(url)
        .unwrap()
        .clear_events()
        .await
        .unwrap();
    assert_eq!(
        request_line(&seen.await.unwrap()[0]),
        "DELETE /events HTTP/1.1"
    );
}

#[tokio::test]
async fn http_error_status_is_error() {
    let (url, _seen) = serve(vec![(400, "text/plain", b"bad".to_vec())]).await;
    let err = SpeculosClient::new(url)
        .unwrap()
        .button(Button::Left, Action::Press)
        .await
        .unwrap_err();
    assert!(matches!(err, SpeculosError::Http(_)), "{err:?}");
}

#[tokio::test]
async fn wait_for_text_matches_existing_log() {
    let (url, _seen) = serve(vec![
        (200, "application/json", events_body(&["Boilerplate"])),
        (
            200,
            "application/json",
            events_body(&["Boilerplate", "Approve transaction"]),
        ),
    ])
    .await;
    let client = SpeculosClient::new(url).unwrap();
    let ev = timeout(WAIT, client.wait_for_text("Approve", WAIT))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.text, "Approve transaction");
}

#[tokio::test]
async fn wait_for_text_times_out() {
    let (url, _seen) = serve(
        (0..50)
            .map(|_| (200, "application/json", events_body(&["Boilerplate"])))
            .collect(),
    )
    .await;
    let client = SpeculosClient::new(url).unwrap();
    let t = Duration::from_millis(300);
    let err = timeout(WAIT, client.wait_for_text("Approve", t))
        .await
        .unwrap()
        .unwrap_err();
    match err {
        SpeculosError::TextNotFound { needle, timeout } => {
            assert_eq!(needle, "Approve");
            assert_eq!(timeout, t);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn screenshot_returns_body() {
    let png = vec![0x89, b'P', b'N', b'G'];
    let (url, seen) = serve(vec![(200, "image/png", png.clone())]).await;
    let got = SpeculosClient::new(url)
        .unwrap()
        .screenshot()
        .await
        .unwrap();
    assert_eq!(got, png);
    assert_eq!(
        request_line(&seen.await.unwrap()[0]),
        "GET /screenshot HTTP/1.1"
    );
}

#[tokio::test]
async fn event_stream_splits_lines() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let req = read_request(&mut sock).await;
        let head =
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
        sock.write_all(head.as_bytes()).await.unwrap();
        sock.write_all(b"{\"text\":\"Boiler").await.unwrap();
        sock.flush().await.unwrap();
        sleep(Duration::from_millis(50)).await;
        sock.write_all(b"plate\",\"x\":1,\"y\":2}\n\n{\"text\":\"Approve\",\"x\":3,\"y\":4}\n")
            .await
            .unwrap();
        let _ = sock.shutdown().await;
        req
    });
    let client = SpeculosClient::new(url).unwrap();
    let events: Vec<_> = timeout(WAIT, client.event_stream().collect::<Vec<_>>())
        .await
        .unwrap();
    let events: Vec<_> = events.into_iter().map(Result::unwrap).collect();
    assert_eq!(
        events,
        vec![
            ScreenEvent {
                text: "Boilerplate".into(),
                x: 1,
                y: 2
            },
            ScreenEvent {
                text: "Approve".into(),
                x: 3,
                y: 4
            },
        ]
    );
    let req = server.await.unwrap();
    assert_eq!(request_line(&req), "GET /events?stream=true HTTP/1.1");
}

#[tokio::test]
async fn wait_for_text_bounded_when_server_hangs() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    // Accept and never reply.
    let _server = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap().0);
        }
    });
    let client = SpeculosClient::new(url).unwrap();
    let t = Duration::from_millis(300);
    let err = timeout(WAIT, client.wait_for_text("Approve", t))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, SpeculosError::TextNotFound { .. }), "{err:?}");
}

#[tokio::test]
async fn event_stream_ends_after_malformed_line() {
    let body = b"not json\n{\"text\":\"Approve\",\"x\":3,\"y\":4}\n".to_vec();
    let (url, _seen) = serve(vec![(200, "text/event-stream", body)]).await;
    let client = SpeculosClient::new(url).unwrap();
    let items: Vec<_> = timeout(WAIT, client.event_stream().collect::<Vec<_>>())
        .await
        .unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(matches!(items[0], Err(SpeculosError::Json(_))));
}
