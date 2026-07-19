//! Subscription update model: replace nodes atomically, preserve the
//! active selection by stable_key, keep old nodes on failure.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use vulpini_core::config::ConfigStore;
use vulpini_core::node::subscription::{add_subscription, update};
use vulpini_core::node::{Node, NodeConfig, NodeSource, SsConfig, SsMethod};

/// Minimal HTTP fixture: serves `body` for every request.
async fn serve_body(body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/sub")
}

fn ss_node(server: &str, port: u16, password: &str) -> NodeConfig {
    NodeConfig::Shadowsocks(SsConfig {
        server: server.into(),
        port,
        method: SsMethod::Aes256Gcm,
        password: password.into(),
    })
}

#[tokio::test]
async fn update_replaces_nodes_and_preserves_active() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let mut store = ConfigStore::load(&path).unwrap();

    // Fixture: two links — one identical to the pre-existing node (same
    // stable_key), one new.
    let links = concat!(
        "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#kept\n",
        "trojan://pw2@new.example.com:443#new\n"
    );
    let body = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, links.as_bytes());
    let url = serve_body(body).await;

    let sub_id = add_subscription(&mut store, "test-sub", &url).unwrap();

    // Pre-existing node from this subscription, currently active.
    let old_node = Node::new(
        "kept".into(),
        NodeSource::Subscription(sub_id),
        ss_node("1.2.3.4", 8388, "pw"),
    );
    let old_stable = old_node.stable_key.clone();
    let old_id = old_node.id;
    store.config_mut().nodes.push(old_node);
    store.config_mut().active_node = Some(old_id);
    store.save().unwrap();

    let outcome = update(&mut store, sub_id).await.unwrap();
    assert_eq!(outcome.added, 2);
    assert_eq!(outcome.removed, 1);

    let config = store.config();
    assert_eq!(config.nodes.len(), 2);
    assert!(
        config.nodes.iter().all(|n| n.id != old_id),
        "old node replaced"
    );

    // Active selection followed the stable_key to the new node id.
    let active = config.active_node.expect("active node preserved");
    let active_node = config.nodes.iter().find(|n| n.id == active).unwrap();
    assert_eq!(active_node.stable_key, old_stable);

    // Metadata updated.
    let sub = &config.subscriptions[0];
    assert_eq!(sub.node_count, 2);
    assert!(sub.last_updated.is_some());
    assert!(sub.last_error.is_none());
}

#[tokio::test]
async fn failed_update_keeps_old_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let mut store = ConfigStore::load(&path).unwrap();

    let sub_id = add_subscription(&mut store, "bad-sub", "http://127.0.0.1:1/down").unwrap();
    let old_node = Node::new(
        "old".into(),
        NodeSource::Subscription(sub_id),
        ss_node("1.2.3.4", 8388, "pw"),
    );
    let old_id = old_node.id;
    store.config_mut().nodes.push(old_node);
    store.save().unwrap();

    assert!(update(&mut store, sub_id).await.is_err());
    let config = store.config();
    assert_eq!(config.nodes.len(), 1);
    assert_eq!(config.nodes[0].id, old_id, "old node kept on failure");
    assert!(config.subscriptions[0].last_error.is_some());
}
