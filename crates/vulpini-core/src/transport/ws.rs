//! WebSocket transport: tungstenite framing over a (possibly TLS) stream,
//! with a byte-stream adapter on top (tokio-tungstenite 0.26 no longer
//! provides AsyncRead/AsyncWrite for WebSocketStream).
//!
//! The `tls` feature of tokio-tungstenite is intentionally off — rustls
//! is the only TLS stack here.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use futures::{SinkExt, StreamExt, ready};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::{WebSocketStream, client_async, tungstenite};

use crate::common::{BoxedStream, CoreError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsConfig {
    #[serde(default = "default_path")]
    pub path: String,
    /// Host header override (CDN fronting). Defaults to the server host.
    #[serde(default)]
    pub host: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}

/// Perform the WS upgrade over `stream` (already connected, maybe TLS).
pub async fn wrap(
    stream: BoxedStream,
    server_host: &str,
    server_port: u16,
    cfg: &WsConfig,
) -> Result<BoxedStream, CoreError> {
    let host_header = cfg
        .host
        .clone()
        .unwrap_or_else(|| format!("{server_host}:{server_port}"));

    let uri = format!("ws://{host_header}{}", cfg.path);
    let request = http::Request::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", &host_header)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .map_err(|e| CoreError::Protocol(format!("bad ws request: {e}")))?;

    let (ws, response) = client_async(request, stream)
        .await
        .map_err(|e| CoreError::Protocol(format!("ws upgrade failed: {e}")))?;
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(CoreError::Protocol(format!(
            "ws upgrade rejected: {}",
            response.status()
        )));
    }
    Ok(Box::pin(WsByteStream::new(ws)))
}

/// TCP connect helper shared by ws transports.
pub async fn tcp_connect(server: &str, port: u16) -> Result<TcpStream, CoreError> {
    let tcp =
        tokio::time::timeout(super::CONNECT_TIMEOUT, TcpStream::connect((server, port))).await??;
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

/// Bridges a WebSocketStream (Stream/Sink of Messages) into an
/// AsyncRead + AsyncWrite byte stream. One write = one binary frame;
/// ping/pong is handled by tungstenite internally.
pub struct WsByteStream {
    ws: WebSocketStream<BoxedStream>,
    read_buf: BytesMut,
    eof: bool,
}

impl WsByteStream {
    pub fn new(ws: WebSocketStream<BoxedStream>) -> Self {
        WsByteStream {
            ws,
            read_buf: BytesMut::new(),
            eof: false,
        }
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self.read_buf.is_empty() && !self.eof {
            match self.ws.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => self.eof = true,
                Poll::Ready(Some(Err(e))) => {
                    self.eof = true;
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    tungstenite::Message::Binary(data) => {
                        self.read_buf.extend_from_slice(&data);
                    }
                    tungstenite::Message::Close(_) => self.eof = true,
                    // Ping/pong/frames are answered by tungstenite; text is
                    // unexpected in this protocol family but skipped harmlessly.
                    _ => continue,
                },
            }
        }
        let n = self.read_buf.len().min(buf.remaining());
        buf.put_slice(&self.read_buf[..n]);
        self.read_buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.ws.poll_ready_unpin(cx)).map_err(io::Error::other)?;
        self.ws
            .start_send_unpin(tungstenite::Message::binary(buf.to_vec()))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ws.poll_flush_unpin(cx).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ws.poll_close_unpin(cx).map_err(io::Error::other)
    }
}
