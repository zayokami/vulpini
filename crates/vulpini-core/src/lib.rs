//! vulpini-core: the proxy engine (inbounds, outbounds, router, nodes, stats).
//!
//! This crate is UI-agnostic: it never depends on Tauri, windows-sys, or any
//! shell concern, and it never creates a tokio Runtime itself — the embedding
//! shell (CLI, Tauri app) owns the runtime.

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke_version() {
        assert!(!super::version().is_empty());
    }
}
