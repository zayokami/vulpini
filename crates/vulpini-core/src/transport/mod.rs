//! Transport layer: how an outbound reaches its server, before the
//! protocol handshake. Composed as an enum (not decorator trait objects)
//! because the MVP needs exactly these shapes.
//!
//!   Trojan = Transport::Tls + trojan header
//!   VLESS  = Transport::{Tcp|Tls|Ws|WsOverTls} + vless header
//!   SS     = raw TCP + AEAD codec (it wraps, so it does not use this)

pub mod tls;
pub mod ws;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::common::{BoxedStream, CoreError};

pub use tls::{NoVerifier, TlsConfig};
pub use ws::WsConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Tls(TlsConfig),
    Ws(WsConfig),
    WsOverTls(WsConfig, TlsConfig),
}

impl Transport {
    /// Connect to `server:port` and wrap per the transport.
    pub async fn connect(&self, server: &str, port: u16) -> Result<BoxedStream, CoreError> {
        match self {
            Transport::Tcp => {
                let tcp = ws::tcp_connect(server, port).await?;
                Ok(Box::pin(tcp))
            }
            Transport::Tls(cfg) => {
                let tcp = ws::tcp_connect(server, port).await?;
                tls::wrap(tcp, server, cfg).await
            }
            Transport::Ws(cfg) => {
                let tcp = ws::tcp_connect(server, port).await?;
                ws::wrap(Box::pin(tcp), server, port, cfg).await
            }
            Transport::WsOverTls(ws_cfg, tls_cfg) => {
                let tcp = ws::tcp_connect(server, port).await?;
                let tls = tls::wrap(tcp, server, tls_cfg).await?;
                ws::wrap(tls, server, port, ws_cfg).await
            }
        }
    }
}
