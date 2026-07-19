use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::node::{Node, NodeId};

/// Persisted application configuration (JSON on disk). Runtime state lives
/// in the engine — never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub version: u32,
    pub listen: SocketAddr,
    #[serde(default)]
    pub active_node: Option<NodeId>,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            version: 1,
            listen: "127.0.0.1:7890".parse().expect("valid default"),
            active_node: None,
            nodes: Vec::new(),
            subscriptions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    /// Unix seconds of the last successful update.
    #[serde(default)]
    pub last_updated: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub node_count: usize,
}

/// Loads, owns and persists [`AppConfig`]. Writes are atomic
/// (temp file + rename) so a crash never leaves a half-written file.
pub struct ConfigStore {
    path: PathBuf,
    config: AppConfig,
}

impl ConfigStore {
    /// Load from `path`; a missing file yields defaults, a corrupt file is
    /// backed up to `<path>.bad` and replaced with defaults.
    pub fn load(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let config = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<AppConfig>(&text) {
                Ok(config) => config,
                Err(e) => {
                    let backup = path.with_extension("bad");
                    warn!(error = %e, backup = %backup.display(), "config corrupt, starting fresh");
                    let _ = std::fs::copy(&path, &backup);
                    AppConfig::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AppConfig::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { path, config })
    }

    pub fn save(&self) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(&self.config).map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut AppConfig {
        &mut self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeConfig, NodeSource, SsConfig, SsMethod};

    fn sample_node() -> Node {
        Node::new(
            "test".into(),
            NodeSource::Manual,
            NodeConfig::Shadowsocks(SsConfig {
                server: "1.2.3.4".into(),
                port: 8388,
                method: SsMethod::Aes256Gcm,
                password: "pw".into(),
            }),
        )
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let mut store = ConfigStore::load(&path).unwrap();
        assert!(store.config().nodes.is_empty());

        let node = sample_node();
        store.config_mut().nodes.push(node.clone());
        store.config_mut().active_node = Some(node.id);
        store.save().unwrap();

        let loaded = ConfigStore::load(&path).unwrap();
        assert_eq!(loaded.config().nodes.len(), 1);
        assert_eq!(loaded.config().nodes[0].name, "test");
        assert_eq!(loaded.config().active_node, Some(node.id));
        assert_eq!(loaded.config().listen, "127.0.0.1:7890".parse().unwrap());
    }

    #[test]
    fn corrupt_file_is_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{ not json").unwrap();

        let store = ConfigStore::load(&path).unwrap();
        assert!(store.config().nodes.is_empty());
        assert!(path.with_extension("bad").exists());
    }

    #[test]
    fn node_config_serde_shape_is_stable() {
        // The on-disk tag must stay "type"/snake_case for forward compat.
        let node = sample_node();
        let json = serde_json::to_string(&node.config).unwrap();
        assert!(json.contains("\"type\":\"shadowsocks\""));
        let back: NodeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, node.config);
    }
}
