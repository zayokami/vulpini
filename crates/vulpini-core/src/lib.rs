//! vulpini-core: the proxy engine (inbounds, outbounds, router, nodes, stats).
//!
//! This crate is UI-agnostic: it never depends on Tauri, windows-sys, or any
//! shell concern, and it never creates a tokio Runtime itself — the embedding
//! shell (CLI, Tauri app) owns the runtime.

pub mod common;
pub mod engine;
pub mod inbound;
pub mod outbound;
pub mod relay;

pub use common::{Address, BoxedStream, CoreError, Network, Session};
pub use engine::EngineHandle;
pub use outbound::{Outbound, OutboundRegistry};
