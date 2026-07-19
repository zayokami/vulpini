pub mod http;
pub mod socks5;

use tokio::net::TcpStream;

use crate::common::{BoxedStream, CoreError};

/// Which protocol an accepted connection speaks. The mixed inbound serves
/// both on one port: SOCKS5 starts with 0x05, HTTP CONNECT with ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Socks5,
    Http,
}

/// Peek at the first byte without consuming it and pick the protocol.
pub async fn detect(stream: &TcpStream) -> Result<InboundKind, CoreError> {
    let mut byte = [0u8; 1];
    let n = stream.peek(&mut byte).await?;
    if n == 0 {
        return Err(CoreError::Protocol(
            "connection closed before greeting".into(),
        ));
    }
    Ok(if byte[0] == 0x05 {
        InboundKind::Socks5
    } else {
        InboundKind::Http
    })
}

pub async fn reply_ok(stream: &mut BoxedStream, kind: InboundKind) -> Result<(), CoreError> {
    match kind {
        InboundKind::Socks5 => socks5::reply_ok(stream).await,
        InboundKind::Http => http::reply_ok(stream).await,
    }
}

pub async fn reply_err(
    stream: &mut BoxedStream,
    kind: InboundKind,
    err: &CoreError,
) -> Result<(), CoreError> {
    match kind {
        InboundKind::Socks5 => socks5::reply_err(stream, err).await,
        InboundKind::Http => http::reply_err(stream, err).await,
    }
}
