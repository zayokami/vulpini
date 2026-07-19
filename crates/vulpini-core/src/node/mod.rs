pub mod link;
pub mod model;

pub use link::{LinkError, parse_link};
pub use model::{
    Node, NodeConfig, NodeId, NodeSource, SsConfig, SsMethod, TrojanConfig, VlessConfig,
    VmessConfig, WsConfig,
};
