use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio::sync::Semaphore;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::HttpProxyConfig;
use crate::traffic_analyzer::{TrafficAnalyzer, RequestInfo};
use crate::behavior_monitor::{BehaviorMonitor, BehaviorRecord, ActionType};
use crate::smart_router::SmartRouter;
use crate::ip_manager::IPManager;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct HttpProtocol {
    config: HttpProxyConfig,
    traffic_analyzer: Arc<parking_lot::Mutex<TrafficAnalyzer>>,
    behavior_monitor: Arc<BehaviorMonitor>,
    smart_router: Arc<parking_lot::Mutex<SmartRouter>>,
    ip_manager: Arc<parking_lot::Mutex<IPManager>>,
}

impl HttpProtocol {
    pub fn new(
        config: HttpProxyConfig,
        traffic_analyzer: Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: Arc<BehaviorMonitor>,
        smart_router: Arc<parking_lot::Mutex<SmartRouter>>,
        ip_manager: Arc<parking_lot::Mutex<IPManager>>,
    ) -> Self {
        Self { config, traffic_analyzer, behavior_monitor, smart_router, ip_manager }
    }

    pub async fn start(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);
        let listener = TcpListener::bind(&addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;

        println!("HTTP proxy server listening on {}", addr);

        let max_conn = self.config.max_connections as usize;
        let semaphore = Arc::new(Semaphore::new(
            if max_conn == 0 { Semaphore::MAX_PERMITS } else { max_conn },
        ));

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            println!("[HTTP] Connection limit ({}) reached, dropping {}", max_conn, peer_addr);
                            drop(socket);
                            continue;
                        }
                    };

                    let traffic_analyzer = self.traffic_analyzer.clone();
                    let behavior_monitor = self.behavior_monitor.clone();
                    let smart_router = self.smart_router.clone();
                    let ip_manager = self.ip_manager.clone();
                    let config = self.config.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        let start = Instant::now();
                        if let Err(e) = Self::handle_connection(
                            socket,
                            peer_addr.to_string(),
                            start,
                            config,
                            &traffic_analyzer,
                            &behavior_monitor,
                            &smart_router,
                            &ip_manager,
                        ).await {
                            println!("[HTTP] Connection error: {}", e);
                        }
                    });
                }
                Err(e) => println!("[HTTP] Accept error: {}", e),
            }
        }
    }

    /// Decode a base64 string to bytes. Returns None on invalid input.
    fn decode_base64(input: &str) -> Option<Vec<u8>> {
        let mut lookup = [0xffu8; 256];
        for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
            lookup[c as usize] = i as u8;
        }
        let input = input.trim().trim_end_matches('=');
        let mut output = Vec::with_capacity((input.len() * 3) / 4 + 1);
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &c in input.as_bytes() {
            let val = lookup[c as usize];
            if val == 0xff {
                return None;
            }
            buf = (buf << 6) | val as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                output.push((buf >> bits) as u8);
            }
        }
        Some(output)
    }

    /// Check Proxy-Authorization header against config. Returns true if auth passes.
    fn check_proxy_auth(request: &str, config: &HttpProxyConfig) -> bool {
        if !config.auth_enabled {
            return true;
        }
        let auth_line = match request.lines().find(|l| l.to_lowercase().starts_with("proxy-authorization:")) {
            Some(l) => l,
            None => return false,
        };
        let value = auth_line.splitn(2, ':').nth(1).unwrap_or("").trim();
        let encoded = match value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")) {
            Some(e) => e,
            None => return false,
        };
        let bytes = match Self::decode_base64(encoded) {
            Some(b) => b,
            None => return false,
        };
        let creds = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut parts = creds.splitn(2, ':');
        let username = parts.next().unwrap_or("");
        let password = parts.next().unwrap_or("");
        match (&config.username, &config.password) {
            (Some(u), Some(p)) => username == u && password == p,
            (Some(u), None) => username == u,
            (None, Some(p)) => password == p,
            (None, None) => true,
        }
    }

    /// Parse host and port from a CONNECT target string (handles IPv6 brackets).
    fn parse_connect_target(host_port: &str) -> Option<(String, u16)> {
        if host_port.starts_with('[') {
            // IPv6: [::1]:443
            let end = host_port.find(']')?;
            let host = host_port[1..end].to_string();
            let port = host_port[end + 1..].trim_start_matches(':').parse().unwrap_or(443);
            Some((host, port))
        } else {
            // hostname:port or IPv4:port
            let (host, port_str) = host_port.rsplit_once(':')?;
            let port = port_str.parse().unwrap_or(443);
            Some((host.to_string(), port))
        }
    }

    /// Parse absolute URL from a plain HTTP request line into (host, port, path).
    fn parse_http_url(request_str: &str) -> Option<(String, u16, String)> {
        let first_line = request_str.lines().next()?;
        let url = first_line.split_whitespace().nth(1)?;
        let rest = url.strip_prefix("http://")?;
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
            None => (host_port.to_string(), 80),
        };
        Some((host, port, path))
    }

    /// Prepare an HTTP request for upstream forwarding:
    /// - Optionally rewrite the first line to use a relative path (None = keep absolute URL)
    /// - Strip Proxy-Authorization and Connection headers
    /// - Inject Connection: close
    fn prepare_forward_request(request: &str, rewrite_path: Option<&str>) -> String {
        let first_line = request.lines().next().unwrap_or("");
        let new_first_line = if let Some(path) = rewrite_path {
            let method = first_line.split_whitespace().next().unwrap_or("GET");
            let version = first_line.split_whitespace().nth(2).unwrap_or("HTTP/1.1");
            format!("{} {} {}\r\n", method, path, version)
        } else {
            format!("{}\r\n", first_line)
        };

        let after_first = match request.find("\r\n") {
            Some(i) => &request[i + 2..],
            None => "",
        };
        let (headers_raw, body) = match after_first.find("\r\n\r\n") {
            Some(i) => (&after_first[..i], &after_first[i + 4..]),
            None => (after_first, ""),
        };

        let filtered: String = headers_raw
            .split("\r\n")
            .filter(|l| {
                let lower = l.to_lowercase();
                !l.is_empty()
                    && !lower.starts_with("proxy-authorization:")
                    && !lower.starts_with("connection:")
            })
            .collect::<Vec<_>>()
            .join("\r\n");

        let sep = if filtered.is_empty() { "" } else { "\r\n" };
        if body.is_empty() {
            format!("{}{}{}Connection: close\r\n\r\n", new_first_line, filtered, sep)
        } else {
            format!("{}{}{}Connection: close\r\n\r\n{}", new_first_line, filtered, sep, body)
        }
    }

    async fn handle_connection(
        mut socket: TcpStream,
        _peer_addr: String,
        start_time: Instant,
        config: HttpProxyConfig,
        traffic_analyzer: &Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: &Arc<BehaviorMonitor>,
        smart_router: &Arc<parking_lot::Mutex<SmartRouter>>,
        ip_manager: &Arc<parking_lot::Mutex<IPManager>>,
    ) -> Result<()> {
        let mut buf = [0u8; 8192];

        let n = match socket.read(&mut buf).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };

        let request_str = String::from_utf8_lossy(&buf[..n]);

        // Authentication check
        if !Self::check_proxy_auth(&request_str, &config) {
            socket.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"Vulpini\"\r\n\
                  Content-Length: 0\r\n\r\n",
            ).await?;
            return Ok(());
        }

        // Resolve upstream proxy if ip_manager has any entries
        let upstream_addr: Option<String> = {
            let manager = ip_manager.lock();
            if manager.is_empty() { None } else { manager.get_proxy_endpoint() }
        };

        if request_str.starts_with("CONNECT ") {
            // ── HTTPS CONNECT tunnel ──────────────────────────────────────────
            let host_port = request_str
                .trim_start_matches("CONNECT ")
                .split_whitespace()
                .next()
                .unwrap_or("");

            let (host, port) = match Self::parse_connect_target(host_port) {
                Some(t) => t,
                None => {
                    socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
                    return Ok(());
                }
            };

            let target = format!("{}:{}", host, port);
            let connect_addr = upstream_addr.as_deref().unwrap_or(&target).to_string();
            let connect_start = Instant::now();

            match timeout(CONNECT_TIMEOUT, TcpStream::connect(&connect_addr)).await {
                Ok(Ok(mut upstream)) => {
                    let latency = connect_start.elapsed();
                    { smart_router.lock().record_result(&target, true, latency); }

                    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

                    let session_id = uuid::Uuid::new_v4().to_string();
                    behavior_monitor.record_action(&session_id.clone(), &BehaviorRecord {
                        session_id,
                        timestamp: start_time,
                        action_type: ActionType::Connect,
                        duration: latency,
                        target: target.clone(),
                        success: true,
                    });

                    {
                        let mut analyzer = traffic_analyzer.lock();
                        analyzer.record_request(RequestInfo {
                            timestamp: start_time,
                            size: n as u64,
                            latency,
                            protocol: "http".to_string(),
                            success: true,
                        });
                    }

                    let (client_to_server, server_to_client) =
                        tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;

                    { traffic_analyzer.lock().record_bytes(server_to_client, client_to_server); }
                }
                Ok(Err(e)) => {
                    let latency = connect_start.elapsed();
                    { smart_router.lock().record_result(&target, false, latency); }
                    { traffic_analyzer.lock().record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency,
                        protocol: "http".to_string(),
                        success: false,
                    }); }
                    socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                    println!("[HTTP] CONNECT failed to {}: {}", connect_addr, e);
                }
                Err(_) => {
                    { smart_router.lock().record_result(&target, false, CONNECT_TIMEOUT); }
                    { traffic_analyzer.lock().record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency: CONNECT_TIMEOUT,
                        protocol: "http".to_string(),
                        success: false,
                    }); }
                    socket.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await?;
                    println!("[HTTP] CONNECT timeout to {}", connect_addr);
                }
            }
        } else if let Some((host, port, path)) = Self::parse_http_url(&request_str) {
            // ── Plain HTTP forwarding ─────────────────────────────────────────
            let target = format!("{}:{}", host, port);
            let connect_addr = upstream_addr.as_deref().unwrap_or(&target).to_string();
            // Keep absolute URL if going through upstream proxy; rewrite to relative otherwise
            let rewrite_path = if upstream_addr.is_none() { Some(path.as_str()) } else { None };
            let forwarded = Self::prepare_forward_request(&request_str, rewrite_path);

            let connect_start = Instant::now();

            match timeout(CONNECT_TIMEOUT, TcpStream::connect(&connect_addr)).await {
                Ok(Ok(mut upstream)) => {
                    let latency = connect_start.elapsed();
                    { smart_router.lock().record_result(&target, true, latency); }

                    upstream.write_all(forwarded.as_bytes()).await?;
                    let (client_to_server, server_to_client) =
                        tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
                    let client_bytes = client_to_server + n as u64;

                    let session_id = uuid::Uuid::new_v4().to_string();
                    behavior_monitor.record_action(&session_id.clone(), &BehaviorRecord {
                        session_id,
                        timestamp: start_time,
                        action_type: ActionType::Request,
                        duration: latency,
                        target: target.clone(),
                        success: true,
                    });

                    {
                        let mut analyzer = traffic_analyzer.lock();
                        analyzer.record_request(RequestInfo {
                            timestamp: start_time,
                            size: n as u64,
                            latency: connect_start.elapsed(),
                            protocol: "http".to_string(),
                            success: true,
                        });
                        analyzer.record_bytes(server_to_client, client_bytes);
                    }
                }
                Ok(Err(e)) => {
                    let latency = connect_start.elapsed();
                    { smart_router.lock().record_result(&target, false, latency); }
                    { traffic_analyzer.lock().record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency,
                        protocol: "http".to_string(),
                        success: false,
                    }); }
                    socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                    println!("[HTTP] forward failed to {}: {}", connect_addr, e);
                }
                Err(_) => {
                    socket.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await?;
                    println!("[HTTP] forward timeout to {}", connect_addr);
                }
            }
        } else {
            socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_base64 ───────────────────────────────────────────────────────

    #[test]
    fn test_decode_base64_simple() {
        // "hello" = "aGVsbG8="
        let decoded = HttpProtocol::decode_base64("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_decode_base64_with_colon() {
        // "user:pass" = "dXNlcjpwYXNz"
        let decoded = HttpProtocol::decode_base64("dXNlcjpwYXNz").unwrap();
        assert_eq!(decoded, b"user:pass");
    }

    #[test]
    fn test_decode_base64_empty() {
        let decoded = HttpProtocol::decode_base64("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_base64_invalid() {
        assert!(HttpProtocol::decode_base64("!!!").is_none());
    }

    // ── check_proxy_auth ────────────────────────────────────────────────────

    fn make_config(auth_enabled: bool, user: Option<&str>, pass: Option<&str>) -> HttpProxyConfig {
        HttpProxyConfig {
            enabled: true,
            listen_address: "127.0.0.1".to_string(),
            listen_port: 8080,
            auth_enabled,
            username: user.map(String::from),
            password: pass.map(String::from),
            max_connections: 1000,
        }
    }

    #[test]
    fn test_auth_disabled_always_passes() {
        let config = make_config(false, None, None);
        assert!(HttpProtocol::check_proxy_auth("GET / HTTP/1.1\r\n\r\n", &config));
    }

    #[test]
    fn test_auth_enabled_no_header_fails() {
        let config = make_config(true, Some("user"), Some("pass"));
        assert!(!HttpProtocol::check_proxy_auth("GET / HTTP/1.1\r\n\r\n", &config));
    }

    #[test]
    fn test_auth_correct_credentials() {
        let config = make_config(true, Some("user"), Some("pass"));
        // "user:pass" -> base64 "dXNlcjpwYXNz"
        let req = "GET / HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert!(HttpProtocol::check_proxy_auth(req, &config));
    }

    #[test]
    fn test_auth_wrong_credentials() {
        let config = make_config(true, Some("user"), Some("pass"));
        // "wrong:creds" -> base64 "d3Jvbmc6Y3JlZHM="
        let req = "GET / HTTP/1.1\r\nProxy-Authorization: Basic d3Jvbmc6Y3JlZHM=\r\n\r\n";
        assert!(!HttpProtocol::check_proxy_auth(req, &config));
    }

    #[test]
    fn test_auth_case_insensitive_header() {
        let config = make_config(true, Some("user"), Some("pass"));
        let req = "GET / HTTP/1.1\r\nproxy-authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert!(HttpProtocol::check_proxy_auth(req, &config));
    }

    #[test]
    fn test_auth_username_only() {
        let config = make_config(true, Some("admin"), None);
        // "admin:" -> base64 "YWRtaW46"
        let req = "GET / HTTP/1.1\r\nProxy-Authorization: Basic YWRtaW46\r\n\r\n";
        assert!(HttpProtocol::check_proxy_auth(req, &config));
    }

    // ── parse_connect_target ────────────────────────────────────────────────

    #[test]
    fn test_parse_connect_host_port() {
        let (host, port) = HttpProtocol::parse_connect_target("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_ipv4() {
        let (host, port) = HttpProtocol::parse_connect_target("1.2.3.4:8080").unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_connect_ipv6() {
        let (host, port) = HttpProtocol::parse_connect_target("[::1]:443").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_default_port() {
        let (host, port) = HttpProtocol::parse_connect_target("[::1]:").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_invalid() {
        assert!(HttpProtocol::parse_connect_target("nocolon").is_none());
    }

    // ── parse_http_url ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_http_url_basic() {
        let req = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (host, port, path) = HttpProtocol::parse_http_url(req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_http_url_with_port() {
        let req = "GET http://example.com:8080/api/data HTTP/1.1\r\n\r\n";
        let (host, port, path) = HttpProtocol::parse_http_url(req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api/data");
    }

    #[test]
    fn test_parse_http_url_no_path() {
        let req = "GET http://example.com HTTP/1.1\r\n\r\n";
        let (host, port, path) = HttpProtocol::parse_http_url(req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_http_url_not_http() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert!(HttpProtocol::parse_http_url(req).is_none());
    }

    // ── prepare_forward_request ─────────────────────────────────────────────

    #[test]
    fn test_prepare_forward_rewrite_path() {
        let req = "GET http://example.com/page HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\n\r\n";
        let result = HttpProtocol::prepare_forward_request(req, Some("/page"));

        assert!(result.starts_with("GET /page HTTP/1.1\r\n"));
        assert!(!result.contains("Proxy-Authorization"));
        assert!(result.contains("Connection: close"));
    }

    #[test]
    fn test_prepare_forward_keep_absolute_url() {
        let req = "GET http://example.com/page HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = HttpProtocol::prepare_forward_request(req, None);

        assert!(result.starts_with("GET http://example.com/page HTTP/1.1\r\n"));
    }

    #[test]
    fn test_prepare_forward_strips_connection_header() {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let result = HttpProtocol::prepare_forward_request(req, Some("/"));

        assert!(!result.contains("keep-alive"));
        assert!(result.contains("Connection: close"));
    }

    #[test]
    fn test_prepare_forward_preserves_body() {
        let req = "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ndata";
        let result = HttpProtocol::prepare_forward_request(req, Some("/api"));

        assert!(result.ends_with("data"));
        assert!(result.contains("Content-Length: 4"));
    }
}
