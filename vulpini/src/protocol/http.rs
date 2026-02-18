use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

use crate::config::HttpProxyConfig;
use crate::traffic_analyzer::{TrafficAnalyzer, RequestInfo};
use crate::behavior_monitor::{BehaviorMonitor, BehaviorRecord, ActionType};
use crate::smart_router::SmartRouter;

pub struct HttpProtocol {
    config: HttpProxyConfig,
    traffic_analyzer: Arc<parking_lot::Mutex<TrafficAnalyzer>>,
    behavior_monitor: Arc<BehaviorMonitor>,
    smart_router: Arc<parking_lot::Mutex<SmartRouter>>,
}

impl HttpProtocol {
    pub fn new(
        config: HttpProxyConfig,
        traffic_analyzer: Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: Arc<BehaviorMonitor>,
        smart_router: Arc<parking_lot::Mutex<SmartRouter>>,
    ) -> Self {
        Self {
            config,
            traffic_analyzer,
            behavior_monitor,
            smart_router,
        }
    }

    pub async fn start(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);
        let listener = TcpListener::bind(&addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;

        println!("HTTP proxy server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    println!("Accepted connection from {}", peer_addr);

                    let traffic_analyzer = self.traffic_analyzer.clone();
                    let behavior_monitor = self.behavior_monitor.clone();
                    let smart_router = self.smart_router.clone();

                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        if let Err(e) = Self::handle_connection(
                            socket,
                            peer_addr.to_string(),
                            start,
                            &traffic_analyzer,
                            &behavior_monitor,
                            &smart_router,
                        ).await {
                            println!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    println!("Accept error: {}", e);
                }
            }
        }
    }

    /// Parse "GET http://host:port/path HTTP/1.1" into (host, port, path)
    fn parse_http_url(request_str: &str) -> Option<(String, u16, String)> {
        let first_line = request_str.lines().next()?;
        let url = first_line.split_whitespace().nth(1)?;
        let rest = url.strip_prefix("http://")?;

        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };

        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
            None => (host_port.to_string(), 80),
        };

        Some((host, port, path))
    }

    async fn handle_connection(
        mut socket: TcpStream,
        peer_addr: String,
        start_time: std::time::Instant,
        traffic_analyzer: &Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: &Arc<BehaviorMonitor>,
        smart_router: &Arc<parking_lot::Mutex<SmartRouter>>,
    ) -> Result<()> {
        let mut buf = [0u8; 8192];

        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    // Record final stats before disconnect
                    let latency = start_time.elapsed();
                    let mut analyzer = traffic_analyzer.lock();
                    analyzer.record_request(RequestInfo {
                        timestamp: start_time,
                        size: 0,
                        latency,
                        protocol: "http".to_string(),
                        success: true,
                    });
                    return Ok(());
                }
                Ok(n) => {
                    let request_str = String::from_utf8_lossy(&buf[..n]);

                    if request_str.starts_with("CONNECT ") {
                        if let Some(host_port) = request_str.trim_start_matches("CONNECT ").split_whitespace().next() {
                            let parts: Vec<&str> = host_port.split(':').collect();
                            let host = parts[0];
                            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

                            let target = format!("{}:{}", host, port);
                            let connect_start = std::time::Instant::now();
                            match TcpStream::connect(&target).await {
                                Ok(mut upstream) => {
                                    let connect_latency = connect_start.elapsed();

                                    // Record router stats
                                    {
                                        let mut router = smart_router.lock();
                                        router.record_result(&target, true, connect_latency);
                                    }

                                    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

                                    // Record behavior
                                    let behavior_record = BehaviorRecord {
                                        session_id: uuid::Uuid::new_v4().to_string(),
                                        timestamp: start_time,
                                        action_type: ActionType::Connect,
                                        duration: connect_latency,
                                        target: target.clone(),
                                        success: true,
                                    };
                                    behavior_monitor.record_action(&peer_addr, &behavior_record);

                                    // Record traffic
                                    {
                                        let mut analyzer = traffic_analyzer.lock();
                                        analyzer.record_request(RequestInfo {
                                            timestamp: start_time,
                                            size: n as u64,
                                            latency: connect_latency,
                                            protocol: "http".to_string(),
                                            success: true,
                                        });
                                    }

                                    let (client_to_server, server_to_client) =
                                        tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;

                                    {
                                        let mut analyzer = traffic_analyzer.lock();
                                        analyzer.record_bytes(server_to_client, client_to_server);
                                    }
                                }
                                Err(e) => {
                                    // Record failed connection
                                    let latency = connect_start.elapsed();
                                    {
                                        let mut router = smart_router.lock();
                                        router.record_result(&target, false, latency);
                                    }
                                    {
                                        let mut analyzer = traffic_analyzer.lock();
                                        analyzer.record_request(RequestInfo {
                                            timestamp: start_time,
                                            size: n as u64,
                                            latency,
                                            protocol: "http".to_string(),
                                            success: false,
                                        });
                                    }

                                    socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                                    println!("Failed to connect to {}:{}: {}", host, port, e);
                                }
                            }
                        } else {
                            socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
                        }
                    } else if let Some(target_info) = Self::parse_http_url(&request_str) {
                        // Regular HTTP proxy request (GET, POST, etc.)
                        let (host, port, path) = target_info;
                        let target = format!("{}:{}", host, port);
                        let connect_start = std::time::Instant::now();

                        match TcpStream::connect(&target).await {
                            Ok(mut upstream) => {
                                let connect_latency = connect_start.elapsed();

                                {
                                    let mut router = smart_router.lock();
                                    router.record_result(&target, true, connect_latency);
                                }

                                // Rewrite request: absolute URL → relative path
                                let first_line = request_str.lines().next().unwrap_or("");
                                let method = first_line.split_whitespace().next().unwrap_or("GET");
                                let rewritten_line = format!("{} {} HTTP/1.1\r\n", method, path);

                                // Get headers after first line, inject Connection: close
                                let rest = match request_str.find("\r\n") {
                                    Some(i) => &request_str[i + 2..],
                                    None => "",
                                };
                                let with_close = match rest.find("\r\n\r\n") {
                                    Some(i) => format!("{}Connection: close\r\n{}", &rest[..i + 2], &rest[i + 2..]),
                                    None => format!("Connection: close\r\n\r\n"),
                                };

                                upstream.write_all(rewritten_line.as_bytes()).await?;
                                upstream.write_all(with_close.as_bytes()).await?;

                                // Relay response back
                                tokio::io::copy(&mut upstream, &mut socket).await?;

                                // Record behavior
                                let behavior_record = BehaviorRecord {
                                    session_id: uuid::Uuid::new_v4().to_string(),
                                    timestamp: start_time,
                                    action_type: ActionType::Request,
                                    duration: connect_latency,
                                    target: target.clone(),
                                    success: true,
                                };
                                behavior_monitor.record_action(&peer_addr, &behavior_record);

                                {
                                    let mut analyzer = traffic_analyzer.lock();
                                    analyzer.record_request(RequestInfo {
                                        timestamp: start_time,
                                        size: n as u64,
                                        latency: connect_start.elapsed(),
                                        protocol: "http".to_string(),
                                        success: true,
                                    });
                                }
                            }
                            Err(e) => {
                                let latency = connect_start.elapsed();
                                {
                                    let mut router = smart_router.lock();
                                    router.record_result(&target, false, latency);
                                }
                                socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                                println!("Failed to connect to {}: {}", target, e);
                            }
                        }
                    } else {
                        socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
                    }
                }
                Err(e) => {
                    println!("Read error: {}", e);
                    return Err(e.into());
                }
            }
        }
    }
}
