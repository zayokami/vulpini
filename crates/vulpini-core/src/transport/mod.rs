//! Transport layer: how an outbound reaches its server, before the
//! protocol handshake. Composed as an enum (not decorator trait objects)
//! because the MVP needs exactly these shapes.
//!
//!   Trojan = Transport::Tls + trojan header
//!   VLESS  = Transport::{Tcp|Tls|Ws|WsOverTls} + vless header
//!   SS     = raw TCP + AEAD codec (it wraps, so it does not use this)

pub mod tls;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use crate::common::{BoxedStream, CoreError};

pub use tls::{NoVerifier, TlsConfig};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Tls(TlsConfig),
}

impl Transport {
    /// Connect to `server:port` and wrap per the transport.
    pub async fn connect(&self, server: &str, port: u16) -> Result<BoxedStream, CoreError> {
        let tcp =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((server, port))).await??;
        tcp.set_nodelay(true).ok();
        match self {
            Transport::Tcp => Ok(Box::pin(tcp)),
            Transport::Tls(cfg) => tls::wrap(tcp, server, cfg).await,
        }
    }
}
