//! ss:// share links: SIP002 and the legacy whole-URI-base64 form.
//!
//! SIP002: ss://base64url(method:password)@host:port/?plugin=...#tag
//! Legacy:  ss://base64(method:password@host:port)#tag
//! Also tolerated: ss://method:password@host:port#tag (unencoded userinfo).
//!
//! SIP003 plugins (obfs, v2ray-plugin) are parsed and rejected clearly.

use crate::node::link::{
    LinkError, b64_decode, b64_encode_url, default_name, parse_query, query_get, split_fragment,
    split_host_port,
};
use crate::node::model::{NodeConfig, SsConfig, SsMethod};

pub fn parse(rest: &str) -> Result<(String, NodeConfig), LinkError> {
    let (rest, name) = split_fragment(rest);

    let (userinfo, authority) = if let Some((userinfo, authority)) = rest.rsplit_once('@') {
        (
            decode_userinfo(userinfo)?,
            strip_query(authority)?.to_string(),
        )
    } else {
        // Legacy form: the entire remainder is one base64 blob.
        let decoded = b64_decode(strip_query(rest)?)?;
        let text = String::from_utf8(decoded)
            .map_err(|_| LinkError::BadFormat("legacy blob is not utf-8".into()))?;
        let (userinfo, authority) = text
            .rsplit_once('@')
            .ok_or_else(|| LinkError::BadFormat("missing '@' in legacy ss link".into()))?;
        (userinfo.to_string(), authority.to_string())
    };
    // SIP002 may place a "/" before the query: host:port/?plugin=...
    let authority = authority.trim_end_matches('/');

    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| LinkError::BadFormat("userinfo missing method:password".into()))?;
    let method = SsMethod::parse(method)
        .ok_or_else(|| LinkError::Unsupported(format!("unsupported cipher '{method}'")))?;

    let (server, port) = split_host_port(authority)?;
    let config = NodeConfig::Shadowsocks(SsConfig {
        server,
        port,
        method,
        password: password.to_string(),
    });
    Ok((name.unwrap_or_else(|| default_name(&config)), config))
}

fn decode_userinfo(userinfo: &str) -> Result<String, LinkError> {
    // SIP002 base64url-encodes userinfo; plain text is tolerated.
    if let Ok(decoded) = b64_decode(userinfo)
        && let Ok(text) = String::from_utf8(decoded)
        && text.contains(':')
    {
        return Ok(text);
    }
    if userinfo.contains(':') {
        Ok(userinfo.to_string())
    } else {
        Err(LinkError::BadFormat("cannot decode ss userinfo".into()))
    }
}

/// Strip an optional "?plugin=..." query; any plugin is unsupported.
fn strip_query(s: &str) -> Result<&str, LinkError> {
    match s.split_once('?') {
        None => Ok(s),
        Some((authority, query)) => {
            let query = parse_query(query);
            if let Some(plugin) = query_get(&query, "plugin") {
                return Err(LinkError::Unsupported(format!(
                    "SIP003 plugin '{plugin}' is not supported"
                )));
            }
            Ok(authority)
        }
    }
}

pub fn render(name: &str, config: &SsConfig) -> String {
    let userinfo = format!("{}:{}", config.method.as_str(), config.password);
    format!(
        "ss://{}@{}:{}#{}",
        b64_encode_url(userinfo.as_bytes()),
        config.server,
        config.port,
        name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(link: &str) -> Result<(String, NodeConfig), LinkError> {
        crate::node::link::parse_link(link)
    }

    #[test]
    fn sip002_form() {
        // ss://base64url(aes-256-gcm:password)@1.2.3.4:8388#test node
        let (name, cfg) =
            parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#test%20node").unwrap();
        assert_eq!(name, "test node");
        match cfg {
            NodeConfig::Shadowsocks(c) => {
                assert_eq!(c.server, "1.2.3.4");
                assert_eq!(c.port, 8388);
                assert_eq!(c.method, SsMethod::Aes256Gcm);
                assert_eq!(c.password, "password");
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn legacy_form() {
        // base64("aes-128-gcm:pw123@example.com:1080")
        let blob = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"aes-128-gcm:pw123@example.com:1080",
        );
        let (name, cfg) = parse(&format!("ss://{blob}")).unwrap();
        assert_eq!(name, "example.com:1080");
        match cfg {
            NodeConfig::Shadowsocks(c) => {
                assert_eq!(c.method, SsMethod::Aes128Gcm);
                assert_eq!(c.password, "pw123");
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn plain_userinfo_tolerated() {
        let (_, cfg) = parse("ss://chacha20-ietf-poly1305:secret@10.0.0.1:443#x").unwrap();
        match cfg {
            NodeConfig::Shadowsocks(c) => {
                assert_eq!(c.method, SsMethod::ChaCha20IetfPoly1305);
                assert_eq!(c.password, "secret");
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn plugin_rejected() {
        let link = "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388/?plugin=obfs-local#x";
        assert!(matches!(parse(link), Err(LinkError::Unsupported(_))));
    }

    #[test]
    fn unknown_cipher_rejected() {
        let link = "ss://cmM0LW1kNTpwdw@1.2.3.4:8388"; // rc4-md5:pw
        assert!(matches!(parse(link), Err(LinkError::Unsupported(_))));
    }

    #[test]
    fn render_parse_roundtrip() {
        let config = SsConfig {
            server: "hk01.example.com".into(),
            port: 8388,
            method: SsMethod::ChaCha20IetfPoly1305,
            password: "p@ss:w0rd".into(),
        };
        let link = render("my node", &config);
        let (name, cfg) = parse(&link).unwrap();
        assert_eq!(name, "my node");
        assert_eq!(cfg, NodeConfig::Shadowsocks(config));
    }
}
