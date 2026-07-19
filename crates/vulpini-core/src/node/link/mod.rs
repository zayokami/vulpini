pub mod ss;
pub mod trojan;
pub mod vless;
pub mod vmess;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use thiserror::Error;

use crate::node::model::NodeConfig;

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("unknown or missing scheme (expected ss://, vmess://, vless://, trojan://)")]
    UnknownScheme,
    #[error("bad base64: {0}")]
    BadBase64(String),
    #[error("bad format: {0}")]
    BadFormat(String),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
}

/// Parse one share link into (display name, node config).
/// Accepts surrounding whitespace; rejects anything unrecognized.
pub fn parse_link(link: &str) -> Result<(String, NodeConfig), LinkError> {
    let link = link.trim();
    if let Some(rest) = strip_scheme(link, "ss") {
        ss::parse(rest)
    } else if let Some(rest) = strip_scheme(link, "vmess") {
        vmess::parse(rest)
    } else if let Some(rest) = strip_scheme(link, "vless") {
        vless::parse(rest)
    } else if let Some(rest) = strip_scheme(link, "trojan") {
        trojan::parse(rest)
    } else {
        Err(LinkError::UnknownScheme)
    }
}

fn strip_scheme<'a>(link: &'a str, scheme: &str) -> Option<&'a str> {
    let prefix = format!("{scheme}://");
    link.get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(&prefix))
        .map(|_| &link[prefix.len()..])
}

/// Real-world links are sloppy: try url-safe and standard alphabets,
/// with and without padding.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, LinkError> {
    let s = s.trim();
    for engine in [&URL_SAFE_NO_PAD, &URL_SAFE, &STANDARD_NO_PAD, &STANDARD] {
        if let Ok(v) = engine.decode(s) {
            return Ok(v);
        }
    }
    Err(LinkError::BadBase64(s.chars().take(32).collect()))
}

pub fn b64_encode_url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

/// Split "host:port" or "[v6]:port". Returns (host, port).
pub fn split_host_port(s: &str) -> Result<(String, u16), LinkError> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| LinkError::BadFormat(format!("missing port in '{s}'")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| LinkError::BadFormat(format!("bad port in '{s}'")))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.is_empty() {
        return Err(LinkError::BadFormat("empty host".into()));
    }
    Ok((host, port))
}

/// Parse a query string into (key, value) pairs, percent-decoded.
/// Tolerates a leading '?'.
pub fn parse_query(s: &str) -> Vec<(String, String)> {
    s.trim_start_matches('?')
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

pub fn query_get<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// Split off the "#name" fragment, percent-decoded. Returns (rest, name).
pub fn split_fragment(s: &str) -> (&str, Option<String>) {
    match s.split_once('#') {
        Some((rest, name)) => {
            let name = percent_decode(name);
            if name.is_empty() {
                (rest, None)
            } else {
                (rest, Some(name))
            }
        }
        None => (s, None),
    }
}

/// Fallback display name when the link carries no fragment.
pub fn default_name(config: &NodeConfig) -> String {
    format!("{}:{}", config.server(), config.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_base64() {
        let payload = b"aes-256-gcm:pw";
        for enc in [
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE.encode(payload),
            STANDARD_NO_PAD.encode(payload),
            STANDARD.encode(payload),
        ] {
            assert_eq!(b64_decode(&enc).unwrap(), payload);
        }
    }

    #[test]
    fn host_port_variants() {
        assert_eq!(
            split_host_port("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(split_host_port("[::1]:80").unwrap(), ("::1".into(), 80));
        assert!(split_host_port("no-port").is_err());
    }

    #[test]
    fn fragment_and_query() {
        let (rest, name) = split_fragment("host:443?security=tls#my%20node");
        assert_eq!(rest, "host:443?security=tls");
        assert_eq!(name.as_deref(), Some("my node"));

        let q = parse_query("?security=tls&type=ws");
        assert_eq!(query_get(&q, "SECURITY"), Some("tls"));
        assert_eq!(query_get(&q, "type"), Some("ws"));
        assert_eq!(query_get(&q, "missing"), None);
    }
}
