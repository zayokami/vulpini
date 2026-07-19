//! VLESS outbound (version 0, no addons): a compact stateless header
//! over tcp/tls/ws transports.
//!
//! Client request header:
//!   version(1B=0) | UUID(16B) | addons_len(1B=0) | cmd(1B: 1=TCP)
//!   | port(2B BE) | atyp(1B) | addr
//! Address encoding: ATYP 1=v4, 2=domain, 3=v6 (NOT the socks5 values),
//! port carried before ATYP, not after the address.
//! Server response starts with 2 bytes (version, addons_len) which are
//! stripped on the read side, after which the stream is raw relay.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::{BoxedStream, CoreError, Session};
use crate::node::VlessConfig;
use crate::outbound::Outbound;
use crate::transport::{Transport, WsConfig, tls::TlsConfig};

pub struct VlessOutbound {
    tag: String,
    config: VlessConfig,
}

impl VlessOutbound {
    pub fn new(config: VlessConfig) -> Self {
        let tag = format!("vless:{}:{}", config.server, config.port);
        VlessOutbound { tag, config }
    }

    fn transport(&self) -> Transport {
        let tls_cfg = || TlsConfig {
            sni: self.config.sni.clone(),
            alpn: Vec::new(),
            allow_insecure: self.config.allow_insecure,
        };
        let ws_cfg = |ws: &crate::node::WsConfig| WsConfig {
            path: ws.path.clone(),
            host: ws.host.clone(),
        };
        match (&self.config.ws, self.config.tls) {
            (None, false) => Transport::Tcp,
            (None, true) => Transport::Tls(tls_cfg()),
            (Some(ws), false) => Transport::Ws(ws_cfg(ws)),
            (Some(ws), true) => Transport::WsOverTls(ws_cfg(ws), tls_cfg()),
        }
    }

    fn encode_header(&self, target: &crate::common::Address) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 255);
        buf.push(0x00); // version
        buf.extend_from_slice(self.config.uuid.as_bytes());
        buf.push(0x00); // addons length
        buf.push(0x01); // cmd: TCP
        buf.extend_from_slice(&target.port().to_be_bytes());
        target.write_vless_addr(&mut buf);
        buf
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_tcp(&self, sess: &Session) -> Result<BoxedStream, CoreError> {
        let mut stream = self
            .transport()
            .connect(&self.config.server, self.config.port)
            .await?;
        let header = self.encode_header(&sess.target);
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(Box::pin(ResponseStrip::new(stream)))
    }
}

/// Strips the 2-byte VLESS response header on first reads; everything
/// after is a raw relay. Writes pass straight through.
struct ResponseStrip {
    inner: BoxedStream,
    header: [u8; 2],
    pos: usize,
}

impl ResponseStrip {
    fn new(inner: BoxedStream) -> Self {
        ResponseStrip {
            inner,
            header: [0; 2],
            pos: 0,
        }
    }
}

impl AsyncRead for ResponseStrip {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.pos < 2 {
            let pos = this.pos;
            let mut rb = ReadBuf::new(&mut this.header[pos..2]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless server closed before response header",
                        )));
                    }
                    this.pos += n;
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ResponseStrip {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;
    use uuid::Uuid;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn header_encoding() {
        let outbound = VlessOutbound::new(VlessConfig {
            server: "s.example.com".into(),
            port: 443,
            uuid: Uuid::parse_str(UUID).unwrap(),
            tls: false,
            ws: None,
            sni: None,
            allow_insecure: false,
        });
        let header = outbound.encode_header(&Address::Domain("target.example".into(), 8443));
        assert_eq!(header[0], 0x00);
        assert_eq!(&header[1..17], Uuid::parse_str(UUID).unwrap().as_bytes());
        assert_eq!(header[17], 0x00);
        assert_eq!(header[18], 0x01);
        assert_eq!(&header[19..21], &8443u16.to_be_bytes());
        assert_eq!(header[21], 0x02); // domain atyp
        assert_eq!(header[22] as usize, "target.example".len());
        assert_eq!(&header[23..], b"target.example");
    }

    #[tokio::test]
    async fn response_strip_handles_partial_header() {
        // Response header arriving byte by byte must still be stripped.
        let (client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            server.write_all(&[0x00]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            server.write_all(&[0x00, b'h', b'i']).await.unwrap();
        });
        let mut stream = ResponseStrip::new(Box::pin(client));
        let mut buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"hi");
    }
}
