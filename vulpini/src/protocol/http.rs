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
    traffic_analyzer: Arc<std::sync::Mutex<TrafficAnalyzer>>,
    behavior_monitor: Arc<BehaviorMonitor>,
    smart_router: Arc<std::sync::Mutex<SmartRouter>>,
}

impl HttpProtocol {
    pub fn new(
        config: HttpProxyConfig,
        traffic_analyzer: Arc<std::sync::Mutex<TrafficAnalyzer>>,
        behavior_monitor: Arc<BehaviorMonitor>,
        smart_router: Arc<std::sync::Mutex<SmartRouter>>,
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

    async fn handle_connection(
        mut socket: TcpStream,
        peer_addr: String,
        start_time: std::time::Instant,
        traffic_analyzer: &Arc<std::sync::Mutex<TrafficAnalyzer>>,
        behavior_monitor: &Arc<BehaviorMonitor>,
        smart_router: &Arc<std::sync::Mutex<SmartRouter>>,
    ) -> Result<()> {
        let mut buf = [0u8; 8192];

        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    // Record final stats before disconnect
                    let latency = start_time.elapsed();
                    let mut analyzer = traffic_analyzer.lock().unwrap();
                    analyzer.record_request(RequestInfo {
                        timestamp: start_time,
                        size: 0,
                        latency,
                        protocol: "http".to_string(),
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
                                        let mut router = smart_router.lock().unwrap();
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
                                        let mut analyzer = traffic_analyzer.lock().unwrap();
                                        analyzer.record_request(RequestInfo {
                                            timestamp: start_time,
                                            size: n as u64,
                                            latency: connect_latency,
                                            protocol: "http".to_string(),
                                        });
                                    }

                                    tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
                                }
                                Err(e) => {
                                    // Record failed connection
                                    let latency = connect_start.elapsed();
                                    {
                                        let mut router = smart_router.lock().unwrap();
                                        router.record_result(&target, false, latency);
                                    }
                                    {
                                        let mut analyzer = traffic_analyzer.lock().unwrap();
                                        analyzer.record_request(RequestInfo {
                                            timestamp: start_time,
                                            size: n as u64,
                                            latency,
                                            protocol: "http".to_string(),
                                        });
                                    }

                                    socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                                    println!("Failed to connect to {}:{}: {}", host, port, e);
                                }
                            }
                        } else {
                            socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
                        }
                    } else {
                        socket.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
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
