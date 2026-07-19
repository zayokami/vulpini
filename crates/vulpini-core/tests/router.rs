//! Router and selector hot-swap tests: both must take effect on a running
//! engine without restarting the listener.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vulpini_core::common::{BoxedStream, CoreError, Session};
use vulpini_core::outbound::{Outbound, OutboundRegistry};
use vulpini_core::router::{Mode, RouteRule};
use vulpini_core::{EngineHandle, Router};

/// Test double: dials the fixed echo address regardless of the session
/// target (a real proxy outbound would connect to its server instead).
struct EchoOutbound {
    echo: std::net::SocketAddr,
}

#[async_trait]
impl Outbound for EchoOutbound {
    fn tag(&self) -> &str {
        "echo-outbound"
    }

    async fn dial_tcp(&self, _sess: &Session) -> Result<BoxedStream, CoreError> {
        let stream = TcpStream::connect(self.echo).await?;
        Ok(Box::pin(stream))
    }
}

async fn start_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// SOCKS5 CONNECT to a domain; returns (success, stream).
async fn socks5_domain_connect(
    proxy: std::net::SocketAddr,
    domain: &str,
    port: u16,
) -> (bool, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    (rep[1] == 0x00, s)
}

async fn assert_echo_roundtrip(s: &mut TcpStream) {
    let payload = b"router test";
    s.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn selector_and_router_hot_swap() {
    let echo = start_echo().await;
    let registry = OutboundRegistry::new();
    let selector = registry.selector();

    // Start in Global mode with NO node selected: dials must fail closed.
    let engine = EngineHandle::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(registry),
        Router::new(Mode::Global, vec![]),
    )
    .await
    .unwrap();
    let proxy = engine.local_addr();

    let (ok, _s) = socks5_domain_connect(proxy, "example.com", 443).await;
    assert!(!ok, "no node selected: connect must fail");

    // Select a node: the same engine now proxies, no restart.
    selector.set(Arc::new(EchoOutbound { echo }));
    let (ok, mut s) = socks5_domain_connect(proxy, "example.com", 443).await;
    assert!(ok, "node selected: connect must succeed");
    assert_echo_roundtrip(&mut s).await;
    drop(s);

    // Hot-swap the router: block a suffix, direct everything else.
    engine.set_router(
        Router::from_config(
            Mode::Rule,
            &[
                "DOMAIN-SUFFIX,blocked.test,block".to_string(),
                "MATCH,proxy".to_string(),
            ],
        )
        .unwrap(),
    );
    let (ok, _s) = socks5_domain_connect(proxy, "ads.blocked.test", 443).await;
    assert!(!ok, "blocked suffix must fail");
    let (ok, mut s) = socks5_domain_connect(proxy, "example.com", 443).await;
    assert!(ok, "MATCH,proxy must still dial");
    assert_echo_roundtrip(&mut s).await;
    drop(s);

    // Hot-swap to Direct mode: proxy bypassed (echo target is loopback,
    // which is always direct anyway — the point is the engine survives).
    engine.set_router(Router::new(Mode::Direct, vec![]));
    let (ok, _s) = socks5_domain_connect(proxy, "unresolvable.invalid", 443).await;
    assert!(
        !ok,
        "direct mode resolves domains locally and must fail here"
    );

    engine.shutdown().await;
}

#[test]
fn rule_display_parse_roundtrip_stability() {
    // Rules stored as strings in config.json must round-trip losslessly.
    let rules = [
        "DOMAIN,example.com,proxy",
        "DOMAIN-SUFFIX,google.com,proxy",
        "DOMAIN-KEYWORD,ads,block",
        "IP-CIDR,10.0.0.0/8,direct",
        "PORT,53,block",
        "MATCH,proxy",
    ];
    for s in rules {
        let rule = RouteRule::parse(s).unwrap();
        assert_eq!(rule.to_string(), s);
    }
}
