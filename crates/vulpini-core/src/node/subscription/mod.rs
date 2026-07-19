//! Subscription fetching, format sniffing, and the update model.
//!
//! Fetch is always DIRECT (never through the proxy) in the MVP.
//! Formats handled, in sniff order: Clash YAML, base64 link list,
//! plain-text link list.

pub mod clash;

use std::time::Duration;

use tracing::{info, warn};
use uuid::Uuid;

use crate::common::CoreError;
use crate::config::{ConfigStore, Subscription};
use crate::node::link::{b64_decode, parse_link};
use crate::node::model::{Node, NodeConfig};
use crate::node::{NodeId, NodeSource};

const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// What changed for one subscription update.
#[derive(Debug, Clone, Copy)]
pub struct UpdateOutcome {
    pub added: usize,
    pub removed: usize,
}

/// Fetch a subscription body with a browser-ish UA (some providers gate
/// on clash-style user agents).
pub async fn fetch(url: &str) -> Result<String, CoreError> {
    crate::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("vulpini/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    Ok(response.text().await?)
}

/// Parse a subscription body into (name, config) pairs, sniffing the
/// format. Per-line failures are collected, not fatal; a total failure
/// is an error.
pub fn parse(body: &str) -> Result<clash::ParsedNodes, CoreError> {
    // 1. Clash YAML
    if let Ok((nodes, errors)) = clash::parse(body)
        && !nodes.is_empty()
    {
        for e in errors {
            warn!("subscription entry skipped: {e}");
        }
        return Ok(nodes);
    }

    // 2. Plain-text link list (one link per line; stray garbage lines are
    // skipped by the line parser). A base64 blob is one long line without
    // "://", so any such line means this is the plain-text form.
    let plain: Vec<_> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if plain.iter().any(|l| l.contains("://")) {
        return parse_link_lines(&plain);
    }

    // 3. base64-encoded link list
    let decoded = b64_decode(body.trim())
        .map_err(|_| CoreError::Protocol("unrecognized subscription format".into()))?;
    let text = String::from_utf8(decoded)
        .map_err(|_| CoreError::Protocol("base64 subscription is not utf-8".into()))?;
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    parse_link_lines(&lines)
}

fn parse_link_lines(lines: &[&str]) -> Result<Vec<(String, NodeConfig)>, CoreError> {
    let mut nodes = Vec::new();
    let mut failures = 0usize;
    for line in lines {
        match parse_link(line) {
            Ok(node) => nodes.push(node),
            Err(e) => {
                failures += 1;
                warn!("subscription line skipped: {e}");
            }
        }
    }
    if nodes.is_empty() {
        Err(CoreError::Protocol(format!(
            "no usable links in subscription ({failures} failures)"
        )))
    } else {
        Ok(nodes)
    }
}

/// Fetch, parse, and atomically replace the nodes of one subscription.
/// Active selection survives via stable_key; delay history joins later.
/// On fetch/parse failure the old nodes are kept and the error is stored.
pub async fn update(store: &mut ConfigStore, sub_id: Uuid) -> Result<UpdateOutcome, CoreError> {
    let url = store
        .config()
        .subscriptions
        .iter()
        .find(|s| s.id == sub_id)
        .map(|s| s.url.clone())
        .ok_or_else(|| CoreError::Protocol(format!("subscription {sub_id} not found")))?;

    let parsed = async {
        let body = fetch(&url).await?;
        parse(&body)
    }
    .await;

    match parsed {
        Ok(nodes) => {
            let config = store.config_mut();
            let old: Vec<(NodeId, String)> = config
                .nodes
                .iter()
                .filter(|n| n.source == NodeSource::Subscription(sub_id))
                .map(|n| (n.id, n.stable_key.clone()))
                .collect();
            let removed = old.len();
            let added = nodes.len();

            config
                .nodes
                .retain(|n| n.source != NodeSource::Subscription(sub_id));
            let mut new_nodes: Vec<Node> = nodes
                .into_iter()
                .map(|(name, cfg)| Node::new(name, NodeSource::Subscription(sub_id), cfg))
                .collect();

            // Follow the active node across the refresh by stable_key.
            if let Some(active_id) = config.active_node
                && let Some((_, old_key)) = old.iter().find(|(id, _)| *id == active_id)
            {
                config.active_node = new_nodes
                    .iter()
                    .find(|n| &n.stable_key == old_key)
                    .map(|n| n.id);
            }

            config.nodes.append(&mut new_nodes);
            if let Some(sub) = config.subscriptions.iter_mut().find(|s| s.id == sub_id) {
                sub.last_updated = Some(unix_now());
                sub.last_error = None;
                sub.node_count = added;
            }
            store.save()?;
            info!(added, removed, "subscription updated");
            Ok(UpdateOutcome { added, removed })
        }
        Err(e) => {
            if let Some(sub) = store
                .config_mut()
                .subscriptions
                .iter_mut()
                .find(|s| s.id == sub_id)
            {
                sub.last_error = Some(e.to_string());
            }
            store.save().ok();
            Err(e)
        }
    }
}

pub fn add_subscription(store: &mut ConfigStore, name: &str, url: &str) -> Result<Uuid, CoreError> {
    let sub = Subscription {
        id: Uuid::new_v4(),
        name: name.to_string(),
        url: url.to_string(),
        last_updated: None,
        last_error: None,
        node_count: 0,
    };
    let id = sub.id;
    store.config_mut().subscriptions.push(sub);
    store.save()?;
    Ok(id)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_base64_link_list() {
        let links = "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#a\ntrojan://pw@b.example.com:443#b";
        let body =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, links.as_bytes());
        let nodes = parse(&body).unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].1, NodeConfig::Shadowsocks(_)));
        assert!(matches!(nodes[1].1, NodeConfig::Trojan(_)));
    }

    #[test]
    fn parse_plain_link_list() {
        let body = "trojan://pw@a.example.com:443#a\nss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#b\n";
        let nodes = parse(body).unwrap();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn parse_garbage_fails() {
        assert!(parse("\u{1f600} not a subscription at all").is_err());
    }

    #[test]
    fn partially_bad_list_keeps_good_lines() {
        let body = "trojan://pw@a.example.com:443#a\nnot-a-link\n";
        let nodes = parse(body).unwrap();
        assert_eq!(nodes.len(), 1);
    }
}
