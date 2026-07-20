//! VLESS end-to-end tests over tcp / tls / ws against a spec-minimal
//! reference server (validates the header, then echoes).

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use vulpini_core::common::Session;
use vulpini_core::node::{VlessConfig, WsConfig};
use vulpini_core::outbound::{Outbound, VlessOutbound};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// Read and validate the VLESS request header, send the 2-byte response
/// header, then echo. Works over any stream (tcp, tls, ws).
async fn vless_server_session<S>(mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut fixed = [0u8; 1 + 16 + 1 + 1 + 2];
        stream.read_exact(&mut fixed).await.unwrap();
        assert_eq!(fixed[0], 0x00, "vless version");
        assert_eq!(
            &fixed[1..17],
            Uuid::parse_str(UUID).unwrap().as_bytes(),
            "vless uuid"
        );
        assert_eq!(fixed[17], 0x00, "addons len");
        assert_eq!(fixed[18], 0x01, "cmd tcp");
        let _port = u16::from_be_bytes([fixed[19], fixed[20]]);

        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await.unwrap();
        let host_len = match atyp[0] {
            0x01 => 4,
            0x03 => 16,
            0x02 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await.unwrap();
                l[0] as usize
            }
            other => panic!("bad vless atyp {other}"),
        };
        let mut host = vec![0u8; host_len];
        stream.read_exact(&mut host).await.unwrap();

        // Response header, then echo.
        stream.write_all(&[0x00, 0x00]).await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        tokio::io::copy(&mut r, &mut w).await.ok();
    });
}

async fn start_server_tcp() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            vless_server_session(tcp).await;
        }
    });
    addr
}

async fn start_server_tls() -> std::net::SocketAddr {
    vulpini_core::ensure_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                vless_server_session(tls).await;
            });
        }
    });
    addr
}

async fn start_server_ws(path: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                use tokio_tungstenite::tungstenite::http::{Request, Response};
                // The Err type here (tungstenite's ErrorResponse) is dictated
                // by accept_hdr_async's callback signature, not our choice.
                #[allow(clippy::result_large_err)]
                let callback = move |req: &Request<()>, res: Response<()>| {
                    assert_eq!(req.uri().path(), path, "ws path must match");
                    Ok::<_, Response<Option<String>>>(res)
                };
                let boxed: vulpini_core::common::BoxedStream = Box::pin(tcp);
                let ws = tokio_tungstenite::accept_hdr_async(boxed, callback)
                    .await
                    .unwrap();
                vless_server_session(vulpini_core::transport::ws::WsByteStream::new(ws)).await;
            });
        }
    });
    addr
}

fn config_for(server: std::net::SocketAddr, tls: bool, ws: Option<WsConfig>) -> VlessConfig {
    VlessConfig {
        server: "127.0.0.1".into(),
        port: server.port(),
        uuid: Uuid::parse_str(UUID).unwrap(),
        tls,
        ws,
        sni: if tls { Some("localhost".into()) } else { None },
        allow_insecure: tls, // self-signed test certs
    }
}

async fn roundtrip(outbound: VlessOutbound) {
    let session = Session::tcp(
        vulpini_core::common::Address::Domain("target.example".into(), 443),
        "test",
    );
    let mut stream = outbound.dial_tcp(&session).await.unwrap();
    let payload = b"vless roundtrip payload";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_exact(&mut buf),
    )
    .await
    .expect("timed out")
    .unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn vless_over_tcp() {
    let server = start_server_tcp().await;
    roundtrip(VlessOutbound::new(config_for(server, false, None))).await;
}

#[tokio::test]
async fn vless_over_tls() {
    let server = start_server_tls().await;
    roundtrip(VlessOutbound::new(config_for(server, true, None))).await;
}

#[tokio::test]
async fn vless_over_ws() {
    let server = start_server_ws("/ray").await;
    roundtrip(VlessOutbound::new(config_for(
        server,
        false,
        Some(WsConfig {
            path: "/ray".into(),
            host: Some("cdn.example.com".into()),
        }),
    )))
    .await;
}
