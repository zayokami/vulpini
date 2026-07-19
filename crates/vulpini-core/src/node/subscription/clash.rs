//! Clash YAML subscription parsing: the `proxies:` list with
//! type-specific fields. Unknown proxy types are skipped with errors
//! reported, so one bad entry never sinks the whole subscription.

use serde::Deserialize;
use uuid::Uuid;

use crate::node::model::{
    NodeConfig, SsConfig, SsMethod, TrojanConfig, VlessConfig, VmessConfig, WsConfig,
};

#[derive(Debug, Deserialize)]
struct ClashDocument {
    #[serde(default)]
    proxies: Vec<ClashProxy>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClashProxy {
    Ss {
        name: String,
        server: String,
        port: u16,
        cipher: String,
        password: String,
        #[serde(default)]
        plugin: Option<String>,
    },
    Trojan {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
    },
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: Uuid,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        network: Option<String>,
        #[serde(default, rename = "ws-opts")]
        ws_opts: Option<WsOpts>,
        #[serde(default)]
        servername: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
    },
    Vmess {
        name: String,
        server: String,
        port: u16,
        uuid: Uuid,
        #[serde(default, rename = "alterId")]
        alter_id: u16,
        #[serde(default)]
        cipher: Option<String>,
        #[serde(default)]
        network: Option<String>,
        #[serde(default, rename = "ws-opts")]
        ws_opts: Option<WsOpts>,
        #[serde(default)]
        tls: bool,
        #[serde(default)]
        servername: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct WsOpts {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    headers: Option<WsHeaders>,
}

#[derive(Debug, Deserialize)]
struct WsHeaders {
    #[serde(default, rename = "Host")]
    host: Option<String>,
}

/// (name, config) pairs parsed from any subscription format.
pub type ParsedNodes = Vec<(String, NodeConfig)>;

/// Parse a Clash YAML document. Returns (nodes, per-entry errors).
pub fn parse(body: &str) -> Result<(ParsedNodes, Vec<String>), CoreError> {
    let doc: ClashDocument = serde_yaml_ng::from_str(body)
        .map_err(|e| CoreError::Protocol(format!("not a clash yaml document: {e}")))?;
    if doc.proxies.is_empty() {
        return Err(CoreError::Protocol("yaml has no 'proxies' entries".into()));
    }

    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for proxy in doc.proxies {
        match convert(proxy) {
            Ok(node) => nodes.push(node),
            Err(e) => errors.push(e),
        }
    }
    Ok((nodes, errors))
}

fn convert(proxy: ClashProxy) -> Result<(String, NodeConfig), String> {
    match proxy {
        ClashProxy::Ss {
            name,
            server,
            port,
            cipher,
            password,
            plugin,
        } => {
            if let Some(plugin) = plugin {
                return Err(format!("{name}: plugin '{plugin}' not supported"));
            }
            let method = SsMethod::parse(&cipher)
                .ok_or_else(|| format!("{name}: unsupported cipher '{cipher}'"))?;
            Ok((
                name,
                NodeConfig::Shadowsocks(SsConfig {
                    server,
                    port,
                    method,
                    password,
                }),
            ))
        }
        ClashProxy::Trojan {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
        } => Ok((
            name,
            NodeConfig::Trojan(TrojanConfig {
                server,
                port,
                password,
                sni,
                allow_insecure: skip_cert_verify,
            }),
        )),
        ClashProxy::Vless {
            name,
            server,
            port,
            uuid,
            tls,
            network,
            ws_opts,
            servername,
            skip_cert_verify,
        } => {
            let ws = match network.as_deref() {
                None | Some("tcp") => None,
                Some("ws") => Some(WsConfig {
                    path: ws_opts
                        .as_ref()
                        .and_then(|o| o.path.clone())
                        .unwrap_or_else(|| "/".into()),
                    host: ws_opts
                        .as_ref()
                        .and_then(|o| o.headers.as_ref())
                        .and_then(|h| h.host.clone()),
                }),
                Some(other) => return Err(format!("{name}: network '{other}' not supported")),
            };
            Ok((
                name,
                NodeConfig::Vless(VlessConfig {
                    server,
                    port,
                    uuid,
                    tls,
                    ws,
                    sni: servername,
                    allow_insecure: skip_cert_verify,
                }),
            ))
        }
        ClashProxy::Vmess {
            name,
            server,
            port,
            uuid,
            alter_id,
            cipher,
            network,
            ws_opts,
            tls,
            servername,
        } => {
            let network = network.unwrap_or_else(|| "tcp".into());
            let ws = if network == "ws" {
                Some(WsConfig {
                    path: ws_opts
                        .as_ref()
                        .and_then(|o| o.path.clone())
                        .unwrap_or_else(|| "/".into()),
                    host: ws_opts
                        .as_ref()
                        .and_then(|o| o.headers.as_ref())
                        .and_then(|h| h.host.clone()),
                })
            } else {
                None
            };
            Ok((
                name,
                NodeConfig::Vmess(VmessConfig {
                    server,
                    port,
                    uuid,
                    alter_id,
                    security: cipher.unwrap_or_else(|| "auto".into()),
                    network,
                    ws,
                    tls,
                    sni: servername,
                }),
            ))
        }
    }
}

use crate::common::CoreError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clash_document_all_types() {
        let yaml = r#"
proxies:
  - name: "hk ss"
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
  - name: "jp trojan"
    type: trojan
    server: jp.example.com
    port: 443
    password: pw2
    sni: cdn.example.com
    skip-cert-verify: true
  - name: "us vless"
    type: vless
    server: us.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: us.example.com
  - name: "tw vmess"
    type: vmess
    server: tw.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    network: tcp
"#;
        let (nodes, errors) = parse(yaml).unwrap();
        assert_eq!(nodes.len(), 4);
        assert!(errors.is_empty());
        assert!(matches!(nodes[0].1, NodeConfig::Shadowsocks(_)));
        match &nodes[1].1 {
            NodeConfig::Trojan(c) => {
                assert!(c.allow_insecure);
                assert_eq!(c.sni.as_deref(), Some("cdn.example.com"));
            }
            _ => panic!("wrong type"),
        }
        match &nodes[2].1 {
            NodeConfig::Vless(c) => {
                assert!(c.tls);
                let ws = c.ws.as_ref().unwrap();
                assert_eq!(ws.path, "/ray");
                assert_eq!(ws.host.as_deref(), Some("us.example.com"));
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn bad_entry_is_reported_not_fatal() {
        let yaml = r#"
proxies:
  - name: "good"
    type: trojan
    server: ok.example.com
    port: 443
    password: pw
  - name: "bad cipher"
    type: ss
    server: x.example.com
    port: 8388
    cipher: rc4-md5
    password: pw
"#;
        let (nodes, errors) = parse(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("rc4-md5"));
    }
}
