//! vmess:// share links: base64 of the v2rayN JSON document.
//! The outbound is post-MVP; parsing is complete so subscriptions that are
//! mostly vmess still import cleanly (nodes show as unsupported at dial time).

use serde_json::Value;
use uuid::Uuid;

use crate::node::link::{LinkError, b64_decode, default_name};
use crate::node::model::{NodeConfig, VmessConfig, WsConfig};

pub fn parse(rest: &str) -> Result<(String, NodeConfig), LinkError> {
    let decoded = b64_decode(rest)?;
    let text = String::from_utf8(decoded)
        .map_err(|_| LinkError::BadFormat("vmess payload is not utf-8".into()))?;
    let doc: Value = serde_json::from_str(&text)
        .map_err(|e| LinkError::BadFormat(format!("vmess payload is not json: {e}")))?;

    let server =
        get_str(&doc, "add").ok_or_else(|| LinkError::BadFormat("vmess missing 'add'".into()))?;
    let port =
        get_u16(&doc, "port").ok_or_else(|| LinkError::BadFormat("vmess missing 'port'".into()))?;
    let uuid_str =
        get_str(&doc, "id").ok_or_else(|| LinkError::BadFormat("vmess missing 'id'".into()))?;
    let uuid = Uuid::parse_str(&uuid_str)
        .map_err(|_| LinkError::BadFormat(format!("bad vmess uuid '{uuid_str}'")))?;

    let network = get_str(&doc, "net").unwrap_or_else(|| "tcp".into());
    let tls = matches!(get_str(&doc, "tls").as_deref(), Some("tls") | Some("TLS"));
    let ws = if network == "ws" {
        Some(WsConfig {
            path: get_str(&doc, "path").unwrap_or_else(|| "/".into()),
            host: get_str(&doc, "host"),
        })
    } else {
        None
    };

    let name = get_str(&doc, "ps");
    let config = NodeConfig::Vmess(VmessConfig {
        server,
        port,
        uuid,
        alter_id: get_u16(&doc, "aid").unwrap_or(0),
        security: get_str(&doc, "scy").unwrap_or_else(|| "auto".into()),
        network,
        ws,
        tls,
        sni: get_str(&doc, "sni"),
    });
    Ok((name.unwrap_or_else(|| default_name(&config)), config))
}

pub fn render(name: &str, config: &VmessConfig) -> String {
    let doc = serde_json::json!({
        "v": "2",
        "ps": name,
        "add": config.server,
        "port": config.port.to_string(),
        "id": config.uuid.to_string(),
        "aid": config.alter_id.to_string(),
        "scy": config.security,
        "net": config.network,
        "type": "none",
        "host": config.ws.as_ref().and_then(|w| w.host.clone()).unwrap_or_default(),
        "path": config.ws.as_ref().map(|w| w.path.clone()).unwrap_or_default(),
        "tls": if config.tls { "tls" } else { "" },
        "sni": config.sni.clone().unwrap_or_default(),
    });
    crate::node::link::b64_encode_url(doc.to_string().as_bytes())
}

/// JSON fields are typed inconsistently in the wild ("443" vs 443).
fn get_str(doc: &Value, key: &str) -> Option<String> {
    match doc.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn get_u16(doc: &Value, key: &str) -> Option<u16> {
    match doc.get(key)? {
        Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(link: &str) -> Result<(String, NodeConfig), LinkError> {
        crate::node::link::parse_link(link)
    }

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn standard_document() {
        let doc = serde_json::json!({
            "v": "2", "ps": "hk node", "add": "hk.example.com", "port": "443",
            "id": UUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": "hk.example.com", "path": "/vmess", "tls": "tls", "sni": ""
        });
        let link = format!(
            "vmess://{}",
            crate::node::link::b64_encode_url(doc.to_string().as_bytes())
        );
        let (name, cfg) = parse(&link).unwrap();
        assert_eq!(name, "hk node");
        match cfg {
            NodeConfig::Vmess(c) => {
                assert_eq!(c.server, "hk.example.com");
                assert_eq!(c.port, 443);
                assert!(c.tls);
                let ws = c.ws.unwrap();
                assert_eq!(ws.path, "/vmess");
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn numeric_port_and_aid() {
        let doc = serde_json::json!({
            "v": "2", "ps": "x", "add": "1.2.3.4", "port": 10086,
            "id": UUID, "aid": 64, "net": "tcp", "tls": ""
        });
        let link = format!(
            "vmess://{}",
            crate::node::link::b64_encode_url(doc.to_string().as_bytes())
        );
        let (_, cfg) = parse(&link).unwrap();
        match cfg {
            NodeConfig::Vmess(c) => {
                assert_eq!(c.port, 10086);
                assert_eq!(c.alter_id, 64);
                assert!(!c.tls);
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn render_parse_roundtrip() {
        let config = VmessConfig {
            server: "tw.example.com".into(),
            port: 443,
            uuid: Uuid::parse_str(UUID).unwrap(),
            alter_id: 0,
            security: "aes-128-gcm".into(),
            network: "ws".into(),
            ws: Some(WsConfig {
                path: "/path".into(),
                host: Some("tw.example.com".into()),
            }),
            tls: true,
            sni: None,
        };
        let (name, cfg) = parse(&format!("vmess://{}", render("tw", &config))).unwrap();
        assert_eq!(name, "tw");
        assert_eq!(cfg, NodeConfig::Vmess(config));
    }
}
