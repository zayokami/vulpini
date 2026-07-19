//! Trojan outbound: TLS transport + a half-page protocol header.
//!
//! Client -> server:
//!   hex(SHA224(password))  (56 lowercase hex chars)
//!   CRLF
//!   SOCKS5-style request: CMD(1) + ATYP + addr + port
//!   CRLF
//! then raw relay both ways.

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::common::{BoxedStream, CoreError, Session};
use crate::node::TrojanConfig;
use crate::outbound::Outbound;
use crate::transport::{Transport, tls::TlsConfig};

pub struct TrojanOutbound {
    tag: String,
    config: TrojanConfig,
}

impl TrojanOutbound {
    pub fn new(config: TrojanConfig) -> Self {
        let tag = format!("trojan:{}:{}", config.server, config.port);
        TrojanOutbound { tag, config }
    }

    /// The 56-char lowercase hex of SHA224(password).
    pub fn password_hash(password: &str) -> String {
        let digest = Sha224::digest(password.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_tcp(&self, sess: &Session) -> Result<BoxedStream, CoreError> {
        let transport = Transport::Tls(TlsConfig {
            sni: self.config.sni.clone(),
            alpn: Vec::new(),
            allow_insecure: self.config.allow_insecure,
        });
        let mut stream = transport
            .connect(&self.config.server, self.config.port)
            .await?;

        let mut header = Vec::with_capacity(56 + 2 + 1 + 1 + 255 + 2 + 2);
        header.extend_from_slice(Self::password_hash(&self.config.password).as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(0x01); // CONNECT
        sess.target.write_socks5(&mut header);
        header.extend_from_slice(b"\r\n");

        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;
    use crate::node::TrojanConfig;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    /// Spec-minimal trojan server: TLS (self-signed) -> validate the
    /// password hash -> parse the address header -> connect out -> relay.
    async fn start_reference_server(
        password: &str,
        connect_to: std::net::SocketAddr,
    ) -> std::net::SocketAddr {
        crate::ensure_crypto_provider();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_hash = TrojanOutbound::password_hash(password);

        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let expected_hash = expected_hash.clone();
                tokio::spawn(async move {
                    let mut tls = acceptor.accept(tcp).await.unwrap();

                    // hex hash (56) + CRLF
                    let mut hash_buf = [0u8; 56];
                    tls.read_exact(&mut hash_buf).await.unwrap();
                    assert_eq!(
                        std::str::from_utf8(&hash_buf).unwrap(),
                        expected_hash,
                        "password hash mismatch"
                    );
                    let mut crlf = [0u8; 2];
                    tls.read_exact(&mut crlf).await.unwrap();
                    assert_eq!(&crlf, b"\r\n");

                    // CMD + address
                    let mut cmd = [0u8; 1];
                    tls.read_exact(&mut cmd).await.unwrap();
                    assert_eq!(cmd[0], 0x01);
                    let mut atyp = [0u8; 1];
                    tls.read_exact(&mut atyp).await.unwrap();
                    let host_len = match atyp[0] {
                        0x01 => 4,
                        0x04 => 16,
                        0x03 => {
                            let mut l = [0u8; 1];
                            tls.read_exact(&mut l).await.unwrap();
                            l[0] as usize
                        }
                        other => panic!("bad atyp {other}"),
                    };
                    let mut host = vec![0u8; host_len + 2];
                    tls.read_exact(&mut host).await.unwrap();
                    tls.read_exact(&mut crlf).await.unwrap();
                    assert_eq!(&crlf, b"\r\n");

                    // Connect out and relay both ways.
                    let target = TcpStream::connect(connect_to).await.unwrap();
                    let (mut tr, mut tw) = target.into_split();
                    let (mut cr, mut cw) = tokio::io::split(tls);
                    tokio::spawn(async move {
                        tokio::io::copy(&mut cr, &mut tw).await.ok();
                    });
                    tokio::io::copy(&mut tr, &mut cw).await.ok();
                });
            }
        });
        addr
    }

    async fn start_echo() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
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

    #[test]
    fn sha224_hash_format() {
        let hash = TrojanOutbound::password_hash("password");
        assert_eq!(hash.len(), 56);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // SHA224("password") — cross-checked with independent tooling.
        assert_eq!(
            hash,
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[tokio::test]
    async fn trojan_end_to_end() {
        let echo = start_echo().await;
        let server = start_reference_server("trojan-pw", echo).await;

        let outbound = TrojanOutbound::new(TrojanConfig {
            server: "127.0.0.1".into(),
            port: server.port(),
            password: "trojan-pw".into(),
            sni: Some("localhost".into()),
            allow_insecure: true, // self-signed test cert
        });
        let session = Session::tcp(Address::Domain("example.com".into(), 443), "test");

        let mut stream = outbound.dial_tcp(&session).await.unwrap();
        let payload = b"through trojan tls";
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
}
