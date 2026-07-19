pub mod block;
pub mod direct;
pub mod selector;
pub mod shadowsocks;
pub mod trojan;
pub mod vless;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::common::{BoxedStream, CoreError, Session};
use crate::node::NodeConfig;

pub use block::BlockOutbound;
pub use direct::DirectOutbound;
pub use selector::Selector;
pub use shadowsocks::ShadowsocksOutbound;
pub use trojan::TrojanOutbound;
pub use vless::VlessOutbound;

/// Tag of the always-present built-in outbounds.
pub const TAG_DIRECT: &str = "direct";
pub const TAG_BLOCK: &str = "block";
/// Tag of the selected-node outbound (a [`Selector`]).
pub const TAG_PROXY: &str = "proxy";

/// Build an outbound from a node configuration. Protocols without an
/// implemented outbound (vmess for now) return `Unsupported`.
pub fn build_outbound(node: &NodeConfig) -> Result<Arc<dyn Outbound>, CoreError> {
    match node {
        NodeConfig::Shadowsocks(c) => Ok(Arc::new(ShadowsocksOutbound::new(c.clone()))),
        NodeConfig::Trojan(c) => Ok(Arc::new(TrojanOutbound::new(c.clone()))),
        NodeConfig::Vless(c) => Ok(Arc::new(VlessOutbound::new(c.clone()))),
        other => Err(CoreError::Unsupported(format!(
            "outbound for protocol '{}' is not implemented yet",
            other.protocol()
        ))),
    }
}

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
    selector: Arc<Selector>,
}

impl OutboundRegistry {
    /// Creates a registry with the built-ins: "direct", "block", and an
    /// empty "proxy" selector (dials fail until a node is set).
    pub fn new() -> Self {
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        map.insert(TAG_DIRECT.into(), Arc::new(DirectOutbound::new()));
        map.insert(TAG_BLOCK.into(), Arc::new(BlockOutbound::new()));
        let selector = Selector::new();
        map.insert(TAG_PROXY.into(), selector.clone());
        Self { map, selector }
    }

    /// The shared selector — set the active node through it.
    pub fn selector(&self) -> Arc<Selector> {
        self.selector.clone()
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
