//! trojan:// share links: trojan://password@host:port?sni=&allowInsecure=#name

use crate::node::link::{
    LinkError, default_name, parse_query, percent_decode, query_get, split_fragment,
    split_host_port,
};
use crate::node::model::{NodeConfig, TrojanConfig};

pub fn parse(rest: &str) -> Result<(String, NodeConfig), LinkError> {
    let (rest, name) = split_fragment(rest);
    let (rest, query) = match rest.split_once('?') {
        Some((a, q)) => (a, parse_query(q)),
        None => (rest, Vec::new()),
    };

    let (password, authority) = rest
        .rsplit_once('@')
        .ok_or_else(|| LinkError::BadFormat("missing '@' in trojan link".into()))?;
    let (server, port) = split_host_port(authority)?;

    let allow_insecure = matches!(
        query_get(&query, "allowInsecure").map(|v| v.to_ascii_lowercase()),
        Some(ref v) if v == "1" || v == "true"
    );

    let config = NodeConfig::Trojan(TrojanConfig {
        server,
        port,
        password: percent_decode(password),
        sni: query_get(&query, "sni").map(|s| s.to_string()),
        allow_insecure,
    });
    Ok((name.unwrap_or_else(|| default_name(&config)), config))
}

pub fn render(name: &str, config: &TrojanConfig) -> String {
    let mut link = format!(
        "trojan://{}@{}:{}",
        config.password, config.server, config.port
    );
    let mut params = Vec::new();
    if let Some(sni) = &config.sni {
        params.push(format!("sni={sni}"));
    }
    if config.allow_insecure {
        params.push("allowInsecure=1".to_string());
    }
    if !params.is_empty() {
        link.push('?');
        link.push_str(&params.join("&"));
    }
    link.push('#');
    link.push_str(name);
    link
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(link: &str) -> Result<(String, NodeConfig), LinkError> {
        crate::node::link::parse_link(link)
    }

    #[test]
    fn basic() {
        let (name, cfg) =
            parse("trojan://p%40ss@trojan.example.com:443?sni=cdn.example.com#tr").unwrap();
        assert_eq!(name, "tr");
        match cfg {
            NodeConfig::Trojan(c) => {
                assert_eq!(c.password, "p@ss");
                assert_eq!(c.server, "trojan.example.com");
                assert_eq!(c.sni.as_deref(), Some("cdn.example.com"));
                assert!(!c.allow_insecure);
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn allow_insecure_flag() {
        let (_, cfg) = parse("trojan://pw@1.2.3.4:443?allowInsecure=1").unwrap();
        match cfg {
            NodeConfig::Trojan(c) => assert!(c.allow_insecure),
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn render_parse_roundtrip() {
        let config = TrojanConfig {
            server: "jp.example.com".into(),
            port: 443,
            password: "secret".into(),
            sni: Some("www.apple.com".into()),
            allow_insecure: true,
        };
        let (name, cfg) = parse(&render("tokyo", &config)).unwrap();
        assert_eq!(name, "tokyo");
        assert_eq!(cfg, NodeConfig::Trojan(config));
    }
}
