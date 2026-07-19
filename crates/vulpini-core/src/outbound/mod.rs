pub mod block;
pub mod direct;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::common::{BoxedStream, CoreError, Session};

pub use block::BlockOutbound;
pub use direct::DirectOutbound;

/// Tag of the always-present built-in outbounds.
pub const TAG_DIRECT: &str = "direct";
pub const TAG_BLOCK: &str = "block";

/// A way out of the proxy: direct, block, or a proxy protocol.
///
/// Implementations must be cheap to construct from node config — switching
/// the active node means building a fresh outbound and swapping it into the
/// selector's `ArcSwap`.
#[async_trait]
pub trait Outbound: Send + Sync + 'static {
    fn tag(&self) -> &str;

    async fn dial_tcp(&self, sess: &Session) -> Result<BoxedStream, CoreError>;

    /// UDP arrives in a later milestone; the stub keeps the trait stable.
    async fn dial_udp(&self, _sess: &Session) -> Result<BoxedStream, CoreError> {
        Err(CoreError::UdpUnsupported)
    }
}

/// All known outbounds by tag. The router's output is always a tag; the
/// registry turns it into something dialable.
pub struct OutboundRegistry {
    map: HashMap<String, Arc<dyn Outbound>>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        map.insert(TAG_DIRECT.into(), Arc::new(DirectOutbound::new()));
        map.insert(TAG_BLOCK.into(), Arc::new(BlockOutbound::new()));
        Self { map }
    }

    pub fn register(&mut self, outbound: Arc<dyn Outbound>) {
        let tag = outbound.tag().to_string();
        self.map.insert(tag, outbound);
    }

    pub fn get(&self, tag: &str) -> Result<Arc<dyn Outbound>, CoreError> {
        self.map
            .get(tag)
            .cloned()
            .ok_or_else(|| CoreError::NoOutbound(tag.into()))
    }
}

impl Default for OutboundRegistry {
    fn default() -> Self {
        Self::new()
    }
}
