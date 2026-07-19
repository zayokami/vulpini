//! Full-stack test: socks5 client -> engine -> SS outbound -> reference
//! SS server (shadowsocks-rust crypto) -> real target.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vulpini_core::EngineHandle;
use vulpini_core::node::{NodeConfig, SsConfig, SsMethod};
use vulpini_core::outbound::shadowsocks::{AeadCipher, SsStream, derive_subkey, evp_bytes_to_key};
use vulpini_core::outbound::{OutboundRegistry, build_outbound};

const TAG_LEN: usize = 16;

type RefCipher = shadowsocks::crypto::v1::Cipher;

fn ref_kind() -> shadowsocks::crypto::CipherKind {
    shadowsocks::crypto::CipherKind::AES_256_GCM
}

async fn ref_read_block(tcp: &mut (impl AsyncReadExt + Unpin), dec: &mut RefCipher) -> Vec<u8> {
    let mut len_block = [0u8; 2 + TAG_LEN];
    tcp.read_exact(&mut len_block).await.unwrap();
    assert!(dec.decrypt_packet(&mut len_block));
    let len = u16::from_be_bytes([len_block[0], len_block[1]]) as usize;
    let mut data = vec![0u8; len + TAG_LEN];
    tcp.read_exact(&mut data).await.unwrap();
    assert!(dec.decrypt_packet(&mut data));
    data.truncate(len);
    data
}

async fn ref_write_block(
    tcp: &mut (impl AsyncWriteExt + Unpin),
    enc: &mut RefCipher,
    payload: &[u8],
) {
    let mut len_block = vec![0u8; 2 + TAG_LEN];
    len_block[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    enc.encrypt_packet(&mut len_block);
    let mut data = vec![0u8; payload.len() + TAG_LEN];
    data[..payload.len()].copy_from_slice(payload);
    enc.encrypt_packet(&mut data);
    tcp.write_all(&len_block).await.unwrap();
    tcp.write_all(&data).await.unwrap();
}

/// A real SS server: reads the address header, connects to the target,
/// relays both directions. Speaks the protocol via shadowsocks-rust crypto.
async fn start_reference_ss_server(password: &str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = evp_bytes_to_key(password.as_bytes(), 32);

    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let key = key.clone();
            tokio::spawn(async move {
                let mut salt = vec![0u8; key.len()];
                tcp.read_exact(&mut salt).await.unwrap();
                let mut dec = RefCipher::new(ref_kind(), &key, &salt);

                let mut enc_salt = vec![0u8; key.len()];
                rand::fill(&mut enc_salt);
                tcp.write_all(&enc_salt).await.unwrap();
                let mut enc = RefCipher::new(ref_kind(), &key, &enc_salt);

                // Address header -> connect out. Domain targets are mapped
                // to loopback: the "remote" server is a local echo.
                let header = ref_read_block(&mut tcp, &mut dec).await;
                let (host, port) = parse_socks5_addr(&header);
                let connect_host = match header[0] {
                    0x03 => "127.0.0.1".to_string(),
                    _ => host,
                };
                let target = TcpStream::connect((connect_host.as_str(), port))
                    .await
                    .unwrap();
                let (mut tr, mut tw) = target.into_split();
                let (mut cr, mut cw) = tcp.into_split();

                let up = async move {
                    loop {
                        let data = match ref_read_block(&mut cr, &mut dec).await {
                            d if d.is_empty() => continue,
                            d => d,
                        };
                        if tw.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                };
                let down = async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        match tr.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => ref_write_block(&mut cw, &mut enc, &buf[..n]).await,
                        }
                    }
                };
                tokio::join!(up, down);
            });
        }
    });
    addr
}

fn parse_socks5_addr(header: &[u8]) -> (String, u16) {
    let port = u16::from_be_bytes([header[header.len() - 2], header[header.len() - 1]]);
    let host = match header[0] {
        0x01 => std::net::Ipv4Addr::new(header[1], header[2], header[3], header[4]).to_string(),
        0x03 => String::from_utf8(header[2..2 + header[1] as usize].to_vec()).unwrap(),
        0x04 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&header[1..17]);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        other => panic!("bad atyp {other}"),
    };
    (host, port)
}

async fn start_plain_echo() -> std::net::SocketAddr {
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

#[tokio::test]
async fn socks5_to_shadowsocks_full_stack() {
    let echo = start_plain_echo().await;
    let ss_server = start_reference_ss_server("fullstack-pw").await;

    // Engine in Global mode with an SS node selected.
    let node = NodeConfig::Shadowsocks(SsConfig {
        server: ss_server.ip().to_string(),
        port: ss_server.port(),
        method: SsMethod::Aes256Gcm,
        password: "fullstack-pw".into(),
    });
    let registry = OutboundRegistry::new();
    registry.selector().set(build_outbound(&node).unwrap());
    let engine = EngineHandle::start(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(registry),
        vulpini_core::Router::new(vulpini_core::Mode::Global, vec![]),
    )
    .await
    .unwrap();

    // SOCKS5 client through the engine; a DOMAIN target (loopback targets
    // are always direct by design, even in Global mode).
    let mut s = TcpStream::connect(engine.local_addr()).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    let host = b"fullstack.test";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "CONNECT through SS must succeed");

    let payload = b"full stack through shadowsocks";
    s.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(&buf, payload);

    drop(s);
    tokio::time::timeout(Duration::from_secs(5), engine.shutdown())
        .await
        .expect("drain hung");
}

/// The SS stream must reassemble ciphertext arriving in arbitrary fragments.
#[test]
fn reassembly_proptest() {
    use proptest::prelude::*;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    proptest!(ProptestConfig::with_cases(16), |(
        chunks in prop::collection::vec(1usize..9000, 1..6),
        frags in prop::collection::vec(1usize..17, 1..64),
    )| {
        rt.block_on(async move {
            let password = "frag-pw";
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let expected: Vec<u8> = chunks
                .iter()
                .enumerate()
                .flat_map(|(i, n)| vec![i as u8; *n])
                .collect();
            let expected_clone = expected.clone();

            tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                // Client salt in, server salt out.
                let mut client_salt = [0u8; 32];
                tcp.read_exact(&mut client_salt).await.unwrap();
                let server_salt = [7u8; 32];
                tcp.write_all(&server_salt).await.unwrap();

                // Encrypt with OUR cipher (the read path under test is ours
                // anyway; interop is covered by the full-stack test).
                let key = evp_bytes_to_key(password.as_bytes(), 32);
                let mut enc = test_enc_cipher(&key, &server_salt);
                let mut wire = Vec::new();
                for (i, n) in chunks.iter().enumerate() {
                    let data = vec![i as u8; *n];
                    wire.extend(enc.encrypt(&(*n as u16).to_be_bytes()));
                    wire.extend(enc.encrypt(&data));
                }
                // Write in awkward fragments.
                let mut off = 0usize;
                let mut i = 0usize;
                while off < wire.len() {
                    let n = frags[i % frags.len()].min(wire.len() - off);
                    tcp.write_all(&wire[off..off + n]).await.unwrap();
                    tcp.flush().await.unwrap();
                    off += n;
                    i += 1;
                }
            });

            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut stream = SsStream::new(tcp, SsMethod::Aes256Gcm, password);
            // Flush the client salt so the server can start talking.
            stream.flush().await.unwrap();
            let mut got = Vec::with_capacity(expected_clone.len());
            tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut got))
                .await
                .expect("timed out")
                .unwrap();
            prop_assert_eq!(got, expected_clone);
            Ok(())
        })?;
    }
    );
}

fn test_enc_cipher(key: &[u8], salt: &[u8]) -> AeadCipher {
    AeadCipher::new(SsMethod::Aes256Gcm, &derive_subkey(salt, key))
}
