pub mod crypto;
pub mod stream;

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::common::{BoxedStream, CoreError, Session};
use crate::node::SsConfig;
use crate::outbound::Outbound;

pub use crypto::{AeadCipher, derive_subkey, evp_bytes_to_key};
pub use stream::SsStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shadowsocks AEAD outbound (aes-128-gcm, aes-256-gcm,
/// chacha20-ietf-poly1305). TCP only for now; UDP arrives later.
pub struct ShadowsocksOutbound {
    tag: String,
    config: SsConfig,
}

impl ShadowsocksOutbound {
    pub fn new(config: SsConfig) -> Self {
        let tag = format!("ss:{}:{}", config.server, config.port);
        ShadowsocksOutbound { tag, config }
    }

    /// Build the SS stream over an already-connected TCP stream.
    /// Writes the target address as the first encrypted payload.
    async fn handshake(&self, tcp: TcpStream, sess: &Session) -> Result<SsStream, CoreError> {
        let mut stream = SsStream::new(tcp, self.config.method, &self.config.password);
        let mut header = Vec::with_capacity(1 + 255 + 2);
        sess.target.write_socks5(&mut header);
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_tcp(&self, sess: &Session) -> Result<BoxedStream, CoreError> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((self.config.server.as_str(), self.config.port)),
        )
        .await??;
        tcp.set_nodelay(true).ok();
        Ok(Box::pin(self.handshake(tcp, sess).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;
    use crate::node::SsMethod;
    use crate::outbound::shadowsocks::crypto::TAG_LEN;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    type RefCipher = shadowsocks::crypto::v1::Cipher;

    fn ref_kind(method: SsMethod) -> shadowsocks::crypto::CipherKind {
        match method {
            SsMethod::Aes128Gcm => shadowsocks::crypto::CipherKind::AES_128_GCM,
            SsMethod::Aes256Gcm => shadowsocks::crypto::CipherKind::AES_256_GCM,
            SsMethod::ChaCha20IetfPoly1305 => shadowsocks::crypto::CipherKind::CHACHA20_POLY1305,
        }
    }

    async fn ref_read_block(tcp: &mut TcpStream, dec: &mut RefCipher) -> Vec<u8> {
        let mut len_block = [0u8; 2 + TAG_LEN];
        tcp.read_exact(&mut len_block).await.unwrap();
        assert!(
            dec.decrypt_packet(&mut len_block),
            "reference: bad length tag"
        );
        let len = u16::from_be_bytes([len_block[0], len_block[1]]) as usize;
        let mut data = vec![0u8; len + TAG_LEN];
        tcp.read_exact(&mut data).await.unwrap();
        assert!(dec.decrypt_packet(&mut data), "reference: bad payload tag");
        data.truncate(len);
        data
    }

    async fn ref_write_block(tcp: &mut TcpStream, enc: &mut RefCipher, payload: &[u8]) {
        let mut len_block = vec![0u8; 2 + TAG_LEN];
        len_block[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        enc.encrypt_packet(&mut len_block);
        let mut data = vec![0u8; payload.len() + TAG_LEN];
        data[..payload.len()].copy_from_slice(payload);
        enc.encrypt_packet(&mut data);
        tcp.write_all(&len_block).await.unwrap();
        tcp.write_all(&data).await.unwrap();
    }

    /// Reference server built on shadowsocks-rust crypto: speaks the SS AEAD
    /// protocol, parses the address header, then echoes block by block.
    async fn start_reference_server(method: SsMethod, password: &str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let key = evp_bytes_to_key(password.as_bytes(), method.key_len());
        let kind = ref_kind(method);

        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tcp.set_nodelay(true).ok();

            // Decrypt direction: keyed by the client's salt.
            let mut salt = vec![0u8; key.len()];
            tcp.read_exact(&mut salt).await.unwrap();
            let mut dec = RefCipher::new(kind, &key, &salt);

            // Encrypt direction: fresh server salt, sent in clear.
            let mut enc_salt = vec![0u8; key.len()];
            rand::fill(&mut enc_salt);
            tcp.write_all(&enc_salt).await.unwrap();
            let mut enc = RefCipher::new(kind, &key, &enc_salt);

            // First block: the target address header.
            let header = ref_read_block(&mut tcp, &mut dec).await;
            assert!([0x01, 0x03, 0x04].contains(&header[0]), "bad atyp");

            // Echo block by block.
            loop {
                let payload = tokio::time::timeout(
                    Duration::from_secs(10),
                    ref_read_block(&mut tcp, &mut dec),
                );
                match payload.await {
                    Ok(data) => ref_write_block(&mut tcp, &mut enc, &data).await,
                    Err(_) => return,
                }
            }
        });
        addr
    }

    fn ss_node(server: std::net::SocketAddr, method: SsMethod, password: &str) -> SsConfig {
        SsConfig {
            server: server.ip().to_string(),
            port: server.port(),
            method,
            password: password.into(),
        }
    }

    #[tokio::test]
    async fn outbound_through_reference_server_all_methods() {
        for method in [
            SsMethod::Aes128Gcm,
            SsMethod::Aes256Gcm,
            SsMethod::ChaCha20IetfPoly1305,
        ] {
            let server = start_reference_server(method, "test-password").await;
            let outbound = ShadowsocksOutbound::new(ss_node(server, method, "test-password"));
            let session = Session::tcp(Address::Domain("example.com".into(), 443), "test");

            let mut stream = outbound.dial_tcp(&session).await.unwrap();
            let payload = b"hello through shadowsocks";
            stream.write_all(payload).await.unwrap();

            let mut buf = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
                .await
                .expect("timed out waiting for echo")
                .unwrap();
            assert_eq!(&buf, payload, "method {:?}", method);
        }
    }

    #[tokio::test]
    async fn large_payload_byte_exact() {
        let method = SsMethod::Aes256Gcm;
        let server = start_reference_server(method, "big").await;
        let outbound = ShadowsocksOutbound::new(ss_node(server, method, "big"));
        let session = Session::tcp(Address::Domain("example.org".into(), 80), "test");

        let mut stream = outbound.dial_tcp(&session).await.unwrap();

        // 1 MiB of deterministic "random" data, exercising many chunks.
        let mut payload = vec![0u8; 1 << 20];
        let mut x: u32 = 0x12345678;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }

        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(30), writer)
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut received))
            .await
            .expect("timed out reading echo")
            .unwrap();
        assert_eq!(received, expected);
    }
}
