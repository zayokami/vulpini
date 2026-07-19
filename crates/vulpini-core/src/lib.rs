//! vulpini-core: the proxy engine (inbounds, outbounds, router, nodes, stats).
//!
//! This crate is UI-agnostic: it never depends on Tauri, windows-sys, or any
//! shell concern, and it never creates a tokio Runtime itself — the embedding
//! shell (CLI, Tauri app) owns the runtime.

pub mod common;
pub mod config;
pub mod engine;
pub mod inbound;
pub mod node;
pub mod outbound;
pub mod relay;
pub mod router;

pub use common::{Address, BoxedStream, CoreError, Network, Session};
pub use config::{AppConfig, ConfigStore};
pub use engine::EngineHandle;
pub use node::{Node, NodeConfig, NodeId};
pub use outbound::{Outbound, OutboundRegistry};
pub use router::{Mode, Router};
