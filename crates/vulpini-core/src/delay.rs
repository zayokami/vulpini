//! Latency testing through a node's real outbound path: build a fresh
//! outbound from the node config (same factory the registry uses), dial
//! a probe URL, and time the full handshake plus first response bytes.
//! Independent of the running engine — works with the core stopped and
//! never perturbs live traffic.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{CoreError, Session, parse_host_port};
use crate::node::NodeConfig;
use crate::outbound::build_outbound;

pub const DEFAULT_PROBE_URL: &str = "http://www.gstatic.com/generate_204";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Measure full connect + protocol handshake + probe response time.
pub async fn test_delay(
    node: &NodeConfig,
    probe_url: &str,
    timeout: Duration,
) -> Result<Duration, CoreError> {
    tokio::time::timeout(timeout, probe(node, probe_url)).await?
}

async fn probe(node: &NodeConfig, probe_url: &str) -> Result<Duration, CoreError> {
    let (host, port, path) = parse_probe_url(probe_url)?;
    let target = parse_host_port(&host, port);

    let outbound = build_outbound(node)?;
    let start = Instant::now();
    let mut stream = outbound
        .dial_tcp(&Session::tcp(target, "delay-test"))
        .await?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: vulpini/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Read until the header terminator (bounded — we only need proof the
    // path works end to end, not the body).
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CoreError::Protocol(
                "probe: connection closed before response".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buf);
    if !head.starts_with("HTTP/") {
        return Err(CoreError::Protocol("probe: not an http response".into()));
    }
    Ok(start.elapsed())
}

fn parse_probe_url(url: &str) -> Result<(String, u16, String), CoreError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| CoreError::Protocol("probe url must be http://".into()))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| CoreError::Protocol(format!("bad probe port in '{url}'")))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(CoreError::Protocol("probe url has empty host".into()));
    }
    Ok((host, port, path))
}

/// One result per node, for concurrent batch testing.
#[derive(Debug, Clone)]
pub struct DelayResult {
    pub node_id: crate::node::NodeId,
    pub delay: Result<Duration, String>,
}

/// Test many nodes concurrently (bounded), yielding results as they
/// complete through the returned stream.
pub fn test_all(
    nodes: Vec<(crate::node::NodeId, NodeConfig)>,
    probe_url: String,
    timeout: Duration,
    concurrency: usize,
) -> impl futures::Stream<Item = DelayResult> {
    use futures::StreamExt;
    futures::stream::iter(nodes.into_iter().map(move |(id, config)| {
        let url = probe_url.clone();
        async move {
            let delay = test_delay(&config, &url, timeout)
                .await
                .map_err(|e| e.to_string());
            DelayResult { node_id: id, delay }
        }
    }))
    .buffer_unordered(concurrency)
}
