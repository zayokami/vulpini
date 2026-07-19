use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::common::{BoxedStream, CoreError, Session};
use crate::outbound::{Outbound, TAG_DIRECT};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects to the target directly. This is the only outbound that resolves
/// domain names locally — every proxy outbound forwards domains as-is.
pub struct DirectOutbound;

impl DirectOutbound {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        TAG_DIRECT
    }

    async fn dial_tcp(&self, sess: &Session) -> Result<BoxedStream, CoreError> {
        let target = sess.target.clone();
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, async move {
            match &target {
                crate::common::Address::Ip(addr) => TcpStream::connect(*addr).await,
                crate::common::Address::Domain(host, port) => {
                    TcpStream::connect((host.as_str(), *port)).await
                }
            }
        })
        .await??;
        stream.set_nodelay(true).ok();
        Ok(Box::pin(stream))
    }
}
