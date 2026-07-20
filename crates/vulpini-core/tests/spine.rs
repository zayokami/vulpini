//! End-to-end tests for the M1 spine: mixed inbound -> direct -> relay.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vulpini_core::EngineHandle;
use vulpini_core::outbound::OutboundRegistry;

/// Start an echo server; returns its address. If `half_close_after` is set,
/// the server shuts down its write side after echoing that many bytes total.
async fn start_echo(half_close_after: Option<usize>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut echoed = 0usize;
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                    echoed += n;
                    if let Some(limit) = half_close_after
                        && echoed >= limit
                    {
                        use tokio::net::tcp::OwnedWriteHalf;
                        let (_r, w): (tokio::net::tcp::OwnedReadHalf, OwnedWriteHalf) =
                            stream.into_split();
                        drop(w); // FIN towards the client
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn start_engine() -> (EngineHandle, std::net::SocketAddr) {
    let registry = Arc::new(OutboundRegistry::new());
    let engine = EngineHandle::start(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        vulpini_core::Router::new(vulpini_core::Mode::Direct, vec![]),
    )
    .await
    .unwrap();
    let addr = engine.local_addr();
    (engine, addr)
}

async fn socks5_connect(proxy: std::net::SocketAddr, target: std::net::SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("test uses v4 only"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[0], 0x05);
    assert_eq!(rep[1], 0x00, "CONNECT must succeed");
    s
}

async fn http_connect(proxy: std::net::SocketAddr, target: std::net::SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 128];
    let n = s.read(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
    s
}

#[tokio::test]
async fn socks5_end_to_end_echo() {
    let echo = start_echo(None).await;
    let (engine, proxy) = start_engine().await;

    let mut s = socks5_connect(proxy, echo).await;
    let payload = b"hello vulpini";
    s.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    drop(s);
    engine.shutdown().await;
}

#[tokio::test]
async fn http_connect_end_to_end_echo() {
    let echo = start_echo(None).await;
    let (engine, proxy) = start_engine().await;

    let mut s = http_connect(proxy, echo).await;
    let payload = b"via http connect";
    s.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    drop(s);
    engine.shutdown().await;
}

#[tokio::test]
async fn half_close_propagates_and_terminates() {
    // Server echoes 5 bytes then FINs its write side. The client must still
    // receive the echoed data, then observe EOF, and the relay task must end
    // (engine shutdown must not hang on the drain).
    let echo = start_echo(Some(5)).await;
    let (engine, proxy) = start_engine().await;

    let mut s = socks5_connect(proxy, echo).await;
    s.write_all(b"12345").await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), async {
        let mut all = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break; // EOF observed: relay terminated upstream->client
            }
            all.extend_from_slice(&buf[..n]);
        }
        all
    })
    .await
    .expect("relay hung on half-close");
    assert_eq!(got, b"12345");

    drop(s);
    tokio::time::timeout(Duration::from_secs(5), engine.shutdown())
        .await
        .expect("engine drain hung");
}

#[tokio::test]
async fn stats_events_tick_with_traffic() {
    let echo = start_echo(None).await;
    let (engine, proxy) = start_engine().await;
    let mut events = engine.events();

    let mut s = socks5_connect(proxy, echo).await;
    let payload = b"count these bytes please";
    s.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await.unwrap();

    // Within ~2.5s the 1 Hz tick must report nonzero traffic and conns.
    let deadline = std::time::Instant::now() + Duration::from_millis(2500);
    let snapshot = loop {
        let ev = tokio::time::timeout_at(deadline.into(), events.recv())
            .await
            .expect("no stats tick received")
            .unwrap();
        let vulpini_core::stats::CoreEvent::Stats(snap) = ev;
        if snap.total_up > 0 && snap.total_down > 0 {
            break snap;
        }
    };
    assert!(snapshot.active_connections >= 1);
    assert!(snapshot.up_rate > 0 || snapshot.total_up > 0);

    drop(s);
    engine.shutdown().await;
}

#[tokio::test]
async fn port_fallback_lands_on_a_free_port() {
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = blocker.local_addr().unwrap();

    let registry = Arc::new(OutboundRegistry::new());
    let engine = EngineHandle::start_with_fallback(
        taken,
        registry,
        vulpini_core::Router::new(vulpini_core::Mode::Direct, vec![]),
    )
    .await
    .expect("fallback should find a free port");

    assert_ne!(
        engine.local_addr().port(),
        taken.port(),
        "must not bind the occupied port"
    );
    engine.shutdown().await;
    drop(blocker);
}

#[tokio::test]
async fn unreachable_target_reports_error() {
    let (engine, proxy) = start_engine().await;

    // Port 1 on loopback refuses connections.
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[0], 0x05);
    assert_ne!(rep[1], 0x00, "failure must be reported, got success");

    drop(s);
    engine.shutdown().await;
}
