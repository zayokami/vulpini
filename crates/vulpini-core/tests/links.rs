//! Golden-corpus and property tests for share-link parsing.

use proptest::prelude::*;
use uuid::Uuid;

use vulpini_core::node::link::parse_link;
use vulpini_core::node::link::{ss, trojan, vless, vmess};
use vulpini_core::node::model::{
    NodeConfig, SsConfig, SsMethod, TrojanConfig, VlessConfig, VmessConfig, WsConfig,
};

#[test]
fn corpus_valid_links_all_parse() {
    let corpus = include_str!("corpus/share_links.txt");
    let mut count = 0;
    for (lineno, line) in corpus.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, config) =
            parse_link(line).unwrap_or_else(|e| panic!("line {} failed: {e}\n{line}", lineno + 1));
        assert!(!name.is_empty(), "line {} produced empty name", lineno + 1);
        // Scheme in the link must match the parsed protocol.
        let scheme = line.split("://").next().unwrap();
        assert_eq!(
            scheme,
            config.protocol(),
            "line {} protocol mismatch",
            lineno + 1
        );
        count += 1;
    }
    assert!(count >= 8, "corpus should contain several links");
}

#[test]
fn corpus_invalid_links_all_fail() {
    let corpus = include_str!("corpus/invalid_links.txt");
    for (lineno, line) in corpus.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            parse_link(line).is_err(),
            "line {} unexpectedly parsed: {line}",
            lineno + 1
        );
    }
}

fn host_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,12}(\\.[a-z][a-z0-9-]{0,12}){0,2}\\.(com|net|org|io)"
}

fn password_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_!~-]{1,24}"
}

fn name_strategy() -> impl Strategy<Value = String> {
    // Trailing whitespace would be eaten by parse_link's trim — ambiguous in
    // real links too, so don't generate it.
    "[a-zA-Z0-9][a-zA-Z0-9 _-]{0,19}".prop_map(|s| s.trim_end().to_string())
}

fn ss_config_strategy() -> impl Strategy<Value = SsConfig> {
    (
        host_strategy(),
        1u16..65535u16,
        prop::sample::select(vec![
            SsMethod::Aes128Gcm,
            SsMethod::Aes256Gcm,
            SsMethod::ChaCha20IetfPoly1305,
        ]),
        password_strategy(),
    )
        .prop_map(|(server, port, method, password)| SsConfig {
            server,
            port,
            method,
            password,
        })
}

fn trojan_config_strategy() -> impl Strategy<Value = TrojanConfig> {
    (
        host_strategy(),
        1u16..65535u16,
        password_strategy(),
        prop::option::of(host_strategy()),
        any::<bool>(),
    )
        .prop_map(
            |(server, port, password, sni, allow_insecure)| TrojanConfig {
                server,
                port,
                password,
                sni,
                allow_insecure,
            },
        )
}

fn vless_config_strategy() -> impl Strategy<Value = VlessConfig> {
    (
        host_strategy(),
        1u16..65535u16,
        any::<bool>(),
        prop::option::of(("/[a-z0-9/]{0,12}", prop::option::of(host_strategy()))),
        prop::option::of(host_strategy()),
    )
        .prop_map(|(server, port, tls, ws, sni)| VlessConfig {
            server,
            port,
            uuid: Uuid::nil(),
            tls,
            ws: ws.map(|(path, host)| WsConfig { path, host }),
            sni,
        })
}

fn vmess_config_strategy() -> impl Strategy<Value = VmessConfig> {
    (
        host_strategy(),
        1u16..65535u16,
        any::<bool>(),
        prop::option::of(("/[a-z0-9/]{0,12}", prop::option::of(host_strategy()))),
    )
        .prop_map(|(server, port, tls, ws)| VmessConfig {
            server,
            port,
            uuid: Uuid::nil(),
            alter_id: 0,
            security: "auto".into(),
            network: if ws.is_some() {
                "ws".into()
            } else {
                "tcp".into()
            },
            ws: ws.map(|(path, host)| WsConfig { path, host }),
            tls,
            sni: None,
        })
}

proptest! {
    #[test]
    fn ss_render_parse_roundtrip(config in ss_config_strategy(), name in name_strategy()) {
        let link = ss::render(&name, &config);
        let (parsed_name, parsed) = parse_link(&link).unwrap();
        prop_assert_eq!(parsed_name, name);
        prop_assert_eq!(parsed, NodeConfig::Shadowsocks(config));
    }

    #[test]
    fn trojan_render_parse_roundtrip(config in trojan_config_strategy(), name in name_strategy()) {
        let link = trojan::render(&name, &config);
        let (parsed_name, parsed) = parse_link(&link).unwrap();
        prop_assert_eq!(parsed_name, name);
        prop_assert_eq!(parsed, NodeConfig::Trojan(config));
    }

    #[test]
    fn vless_render_parse_roundtrip(config in vless_config_strategy(), name in name_strategy()) {
        let link = vless::render(&name, &config);
        let (parsed_name, parsed) = parse_link(&link).unwrap();
        prop_assert_eq!(parsed_name, name);
        prop_assert_eq!(parsed, NodeConfig::Vless(config));
    }

    #[test]
    fn vmess_render_parse_roundtrip(config in vmess_config_strategy(), name in name_strategy()) {
        let link = format!("vmess://{}", vmess::render(&name, &config));
        let (parsed_name, parsed) = parse_link(&link).unwrap();
        prop_assert_eq!(parsed_name, name);
        prop_assert_eq!(parsed, NodeConfig::Vmess(config));
    }
}
