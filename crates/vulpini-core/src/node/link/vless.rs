//! vless:// share links:
//! vless://uuid@host:port?security=tls|none&type=tcp|ws&path=&host=&sni=&flow=#name
//!
//! REALITY, XTLS flows and non-tcp/ws networks are parsed but rejected with
//! explicit "not supported" errors (post-MVP features).

use uuid::Uuid;

use crate::node::link::{
    LinkError, default_name, parse_query, query_get, split_fragment, split_host_port,
};
use crate::node::model::{NodeConfig, VlessConfig, WsConfig};

pub fn parse(rest: &str) -> Result<(String, NodeConfig), LinkError> {
    let (rest, name) = split_fragment(rest);
    let (rest, query) = match rest.split_once('?') {
        Some((a, q)) => (a, parse_query(q)),
        None => (rest, Vec::new()),
    };

    let (uuid, authority) = rest
        .rsplit_once('@')
        .ok_or_else(|| LinkError::BadFormat("missing '@' in vless link".into()))?;
    let uuid =
        Uuid::parse_str(uuid).map_err(|_| LinkError::BadFormat(format!("bad uuid '{uuid}'")))?;
    let (server, port) = split_host_port(authority)?;

    // Reject post-MVP features explicitly so users get a clear message.
    if let Some(flow) = query_get(&query, "flow")
        && !flow.is_empty()
    {
        return Err(LinkError::Unsupported(format!(
            "vless flow '{flow}' is not supported yet"
        )));
    }
    let tls = match query_get(&query, "security").unwrap_or("none") {
        s if s.eq_ignore_ascii_case("tls") => true,
        s if s.eq_ignore_ascii_case("none") || s.is_empty() => false,
        s if s.eq_ignore_ascii_case("reality") => {
            return Err(LinkError::Unsupported(
                "vless REALITY is not supported yet".into(),
            ));
        }
        other => {
            return Err(LinkError::Unsupported(format!("vless security '{other}'")));
        }
    };

    let ws = match query_get(&query, "type").unwrap_or("tcp") {
        t if t.eq_ignore_ascii_case("tcp") => None,
        t if t.eq_ignore_ascii_case("ws") => Some(WsConfig {
            path: query_get(&query, "path")
                .map(|p| p.to_string())
                .unwrap_or_else(|| "/".into()),
            host: query_get(&query, "host").map(|h| h.to_string()),
        }),
        other => {
            return Err(LinkError::Unsupported(format!("vless network '{other}'")));
        }
    };

    let allow_insecure = matches!(
        query_get(&query, "allowInsecure").map(|v| v.to_ascii_lowercase()),
        Some(ref v) if v == "1" || v == "true"
    );

    let config = NodeConfig::Vless(VlessConfig {
        server,
        port,
        uuid,
        tls,
        ws,
        sni: query_get(&query, "sni").map(|s| s.to_string()),
        allow_insecure,
    });
    Ok((name.unwrap_or_else(|| default_name(&config)), config))
}

pub fn render(name: &str, config: &VlessConfig) -> String {
    let mut params = vec![format!(
        "security={}",
        if config.tls { "tls" } else { "none" }
    )];
    match &config.ws {
        Some(ws) => {
            params.push("type=ws".into());
            params.push(format!("path={}", ws.path));
            if let Some(host) = &ws.host {
                params.push(format!("host={host}"));
            }
        }
        None => params.push("type=tcp".into()),
    }
    if let Some(sni) = &config.sni {
        params.push(format!("sni={sni}"));
    }
    format!(
        "vless://{}@{}:{}?{}#{}",
        config.uuid,
        config.server,
        config.port,
        params.join("&"),
        name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn parse(link: &str) -> Result<(String, NodeConfig), LinkError> {
        crate::node::link::parse_link(link)
    }

    #[test]
    fn tcp_tls() {
        let link = format!("vless://{UUID}@us.example.com:443?security=tls&sni=www.example.com#us");
        let (name, cfg) = parse(&link).unwrap();
        assert_eq!(name, "us");
        match cfg {
            NodeConfig::Vless(c) => {
                assert!(c.tls);
                assert!(c.ws.is_none());
                assert_eq!(c.sni.as_deref(), Some("www.example.com"));
                assert_eq!(c.uuid.to_string(), UUID);
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn ws_no_tls() {
        let link =
            format!("vless://{UUID}@cdn.example.com:80?type=ws&path=%2Fray&host=cdn.example.com");
        let (_, cfg) = parse(&link).unwrap();
        match cfg {
            NodeConfig::Vless(c) => {
                assert!(!c.tls);
                let ws = c.ws.unwrap();
                assert_eq!(ws.path, "/ray");
                assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn reality_rejected() {
        let link = format!("vless://{UUID}@x.example.com:443?security=reality&pbk=abc");
        assert!(matches!(parse(&link), Err(LinkError::Unsupported(_))));
    }

    #[test]
    fn flow_rejected() {
        let link = format!("vless://{UUID}@x.example.com:443?flow=xtls-rprx-vision");
        assert!(matches!(parse(&link), Err(LinkError::Unsupported(_))));
    }

    #[test]
    fn render_parse_roundtrip() {
        let config = VlessConfig {
            server: "sg.example.com".into(),
            port: 8443,
            uuid: Uuid::parse_str(UUID).unwrap(),
            tls: true,
            ws: Some(WsConfig {
                path: "/ws".into(),
                host: Some("sg.example.com".into()),
            }),
            sni: Some("sg.example.com".into()),
            allow_insecure: false,
        };
        let (name, cfg) = parse(&render("sg", &config)).unwrap();
        assert_eq!(name, "sg");
        assert_eq!(cfg, NodeConfig::Vless(config));
    }
}
