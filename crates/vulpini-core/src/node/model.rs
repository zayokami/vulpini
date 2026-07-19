use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Internal identity of a node. Random per node; do not confuse with
/// `stable_key`, which identifies a server across subscription refreshes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub Uuid);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// First 8 hex chars, for compact display and CLI prefix matching.
    pub fn short(&self) -> String {
        self.0.simple().to_string()[..8].to_string()
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSource {
    Manual,
    Subscription(Uuid),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    /// hash(proto|server|port|credential) — survives subscription refreshes,
    /// used to keep delay history and the active selection stable.
    pub stable_key: String,
    pub name: String,
    pub source: NodeSource,
    pub config: NodeConfig,
}

impl Node {
    pub fn new(name: String, source: NodeSource, config: NodeConfig) -> Self {
        let stable_key = config.stable_key();
        Node {
            id: NodeId::new(),
            stable_key,
            name,
            source,
            config,
        }
    }
}

/// Per-protocol node configuration. serde-tagged so the config file stays
/// self-describing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeConfig {
    Shadowsocks(SsConfig),
    Trojan(TrojanConfig),
    Vless(VlessConfig),
    /// Parsed and stored now; the outbound arrives after the MVP.
    Vmess(VmessConfig),
}

impl NodeConfig {
    pub fn protocol(&self) -> &'static str {
        match self {
            NodeConfig::Shadowsocks(_) => "ss",
            NodeConfig::Trojan(_) => "trojan",
            NodeConfig::Vless(_) => "vless",
            NodeConfig::Vmess(_) => "vmess",
        }
    }

    pub fn server(&self) -> &str {
        match self {
            NodeConfig::Shadowsocks(c) => &c.server,
            NodeConfig::Trojan(c) => &c.server,
            NodeConfig::Vless(c) => &c.server,
            NodeConfig::Vmess(c) => &c.server,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            NodeConfig::Shadowsocks(c) => c.port,
            NodeConfig::Trojan(c) => c.port,
            NodeConfig::Vless(c) => c.port,
            NodeConfig::Vmess(c) => c.port,
        }
    }

    /// The secret that identifies the account: password or UUID.
    fn credential(&self) -> String {
        match self {
            NodeConfig::Shadowsocks(c) => format!("{:?}|{}", c.method, c.password),
            NodeConfig::Trojan(c) => c.password.clone(),
            NodeConfig::Vless(c) => c.uuid.to_string(),
            NodeConfig::Vmess(c) => c.uuid.to_string(),
        }
    }

    pub fn stable_key(&self) -> String {
        let material = format!(
            "{}|{}|{}|{}",
            self.protocol(),
            self.server().to_ascii_lowercase(),
            self.port(),
            self.credential()
        );
        let digest = Sha256::digest(material.as_bytes());
        digest[..8].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Shadowsocks AEAD ciphers supported by the MVP. 2022-blake3 ciphers are
/// deliberately out of scope for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsMethod {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    ChaCha20IetfPoly1305,
}

impl SsMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            SsMethod::Aes128Gcm => "aes-128-gcm",
            SsMethod::Aes256Gcm => "aes-256-gcm",
            SsMethod::ChaCha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "aes-128-gcm" => Some(SsMethod::Aes128Gcm),
            "aes-256-gcm" => Some(SsMethod::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(SsMethod::ChaCha20IetfPoly1305),
            _ => None,
        }
    }

    /// Master key length in bytes (EVP_BytesToKey output).
    pub fn key_len(&self) -> usize {
        match self {
            SsMethod::Aes128Gcm => 16,
            SsMethod::Aes256Gcm | SsMethod::ChaCha20IetfPoly1305 => 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SsConfig {
    pub server: String,
    pub port: u16,
    pub method: SsMethod,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
}

/// WebSocket transport settings shared by VLESS and VMess.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WsConfig {
    #[serde(default = "default_ws_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
}

fn default_ws_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    /// security=tls
    #[serde(default)]
    pub tls: bool,
    /// type=ws when present, tcp when absent
    #[serde(default)]
    pub ws: Option<WsConfig>,
    #[serde(default)]
    pub sni: Option<String>,
    /// Skip certificate verification (allowInsecure=1 in links).
    #[serde(default)]
    pub allow_insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    #[serde(default)]
    pub alter_id: u16,
    /// Body cipher: "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero".
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// "tcp" | "ws" | others (stored but not necessarily supported later).
    #[serde(default = "default_vmess_network")]
    pub network: String,
    #[serde(default)]
    pub ws: Option<WsConfig>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

fn default_vmess_network() -> String {
    "tcp".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_key_is_stable_and_sensitive() {
        let a = NodeConfig::Trojan(TrojanConfig {
            server: "Example.com".into(),
            port: 443,
            password: "pw".into(),
            sni: None,
            allow_insecure: false,
        });
        let same = a.clone();
        assert_eq!(a.stable_key(), same.stable_key());

        let other_port = NodeConfig::Trojan(TrojanConfig {
            port: 8443,
            ..match &a {
                NodeConfig::Trojan(c) => c.clone(),
                _ => unreachable!(),
            }
        });
        assert_ne!(a.stable_key(), other_port.stable_key());
    }

    #[test]
    fn ss_method_roundtrip() {
        for m in [
            SsMethod::Aes128Gcm,
            SsMethod::Aes256Gcm,
            SsMethod::ChaCha20IetfPoly1305,
        ] {
            assert_eq!(SsMethod::parse(m.as_str()), Some(m));
        }
        assert_eq!(SsMethod::parse("rc4-md5"), None);
    }
}
