use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

use crate::config::Socks5Config;
use crate::traffic_analyzer::{TrafficAnalyzer, RequestInfo};
use crate::behavior_monitor::{BehaviorMonitor, BehaviorRecord, ActionType};
use crate::ip_manager::IPManager;
use crate::smart_router::SmartRouter;

const SOCKS5_VERSION: u8 = 0x05;

pub struct Socks5Protocol {
    config: Socks5Config,
    traffic_analyzer: Arc<parking_lot::Mutex<TrafficAnalyzer>>,
    behavior_monitor: Arc<BehaviorMonitor>,
    ip_manager: Arc<parking_lot::Mutex<IPManager>>,
    smart_router: Arc<parking_lot::Mutex<SmartRouter>>,
}

impl Socks5Protocol {
    pub fn new(
        config: Socks5Config,
        traffic_analyzer: Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: Arc<BehaviorMonitor>,
        ip_manager: Arc<parking_lot::Mutex<IPManager>>,
        smart_router: Arc<parking_lot::Mutex<SmartRouter>>,
    ) -> Self {
        Self {
            config,
            traffic_analyzer,
            behavior_monitor,
            ip_manager,
            smart_router,
        }
    }

    pub async fn start(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);
        let listener = TcpListener::bind(&addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;

        println!("SOCKS5 server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    println!("Accepted connection from {}", peer_addr);

                    let traffic_analyzer = self.traffic_analyzer.clone();
                    let behavior_monitor = self.behavior_monitor.clone();
                    let ip_manager = self.ip_manager.clone();
                    let smart_router = self.smart_router.clone();
                    let config = self.config.clone();

                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        if let Err(e) = Self::handle_connection(
                            socket,
                            peer_addr.to_string(),
                            start,
                            config,
                            &traffic_analyzer,
                            &behavior_monitor,
                            &ip_manager,
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
        config: crate::config::Socks5Config,
        traffic_analyzer: &Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: &Arc<BehaviorMonitor>,
        ip_manager: &Arc<parking_lot::Mutex<IPManager>>,
        smart_router: &Arc<parking_lot::Mutex<SmartRouter>>,
    ) -> Result<()> {
        let mut buf = [0u8; 262];

        let n = socket.read(&mut buf).await.context("Failed to read greeting")?;
        if n < 3 {
            return Ok(());
        }

        if buf[0] != SOCKS5_VERSION {
            return Ok(());
        }

        let auth_enabled = config.auth_enabled;
        let expected_username = config.username.as_deref();
        let expected_password = config.password.as_deref();

        if auth_enabled {
            let method_count = buf[1] as usize;
            let mut supports_userpass = false;
            for i in 0..method_count {
                if 2 + i < n && buf[2 + i] == 0x02 {
                    supports_userpass = true;
                    break;
                }
            }

            if !supports_userpass {
                socket.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
                return Ok(());
            }

            socket.write_all(&[SOCKS5_VERSION, 0x02]).await?;

            let n = socket.read(&mut buf).await.context("Failed to read auth")?;
            if n < 5 || buf[0] != 0x01 {
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }

            let ulen = buf[1] as usize;
            let plen = buf[2 + ulen] as usize;

            if 2 + ulen + plen > n as usize {
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }

            let username = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
            let password = String::from_utf8_lossy(&buf[3 + ulen..3 + ulen + plen]).to_string();

            let auth_ok = match (expected_username, expected_password) {
                (Some(exp_user), Some(exp_pass)) =>
                    username == exp_user && password == exp_pass,
                (Some(exp_user), None) =>
                    username == exp_user,
                (None, Some(exp_pass)) =>
                    password == exp_pass,
                _ => true,
            };

            if auth_ok {
                println!("[AUTH] Successful auth for user: {}", username);
                socket.write_all(&[0x01, 0x00]).await?;
            } else {
                println!("[AUTH] Failed auth attempt for user: {}", username);
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
        } else {
            socket.write_all(&[SOCKS5_VERSION, 0x00]).await?;
        }

        let n = socket.read(&mut buf).await.context("Failed to read request")?;
        if n < 4 {
            return Ok(());
        }

        let atyp = buf[3];

        let (target_addr, target_port) = if atyp == 0x01 {
            // IPv4: [IP(4)] [PORT(2)]
            if n < 10 {
                return Ok(());
            }
            let addr = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (addr, port)
        } else if atyp == 0x03 {
            // Domain: [LEN(1)] [DOMAIN(LEN)] [PORT(2)]
            let domain_len = buf[4] as usize;
            if n < 5 + domain_len + 2 {
                return Ok(());
            }
            let addr = String::from_utf8_lossy(&buf[5..5 + domain_len]).to_string();
            let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
            (addr, port)
        } else {
            return Ok(());
        };

        // Get upstream proxy if available
        let upstream_addr = {
            let manager = ip_manager.lock();
            if manager.is_empty() {
                None
            } else {
                manager.get_proxy_endpoint()
            }
        };

        let connect_start = std::time::Instant::now();
        let connect_result = if let Some(upstream) = upstream_addr {
            TcpStream::connect(&upstream).await
        } else {
            TcpStream::connect(format!("{}:{}", target_addr, target_port)).await
        };
        let connect_latency = connect_start.elapsed();

        let mut upstream = match connect_result {
            Ok(u) => {
                // Success reply: VER(1) REP(1) RSV(1) ATYP(1) ADDR(4) PORT(2) = 10 bytes
                socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                u
            }
            Err(e) => {
                // Failure reply: REP=0x05 (connection refused)
                socket.write_all(&[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;

                let latency = start_time.elapsed();
                {
                    let mut analyzer = traffic_analyzer.lock();
                    analyzer.record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency,
                        protocol: "socks5".to_string(),
                        success: false,
                    });
                    analyzer.record_bytes(n as u64, 0);
                }

                {
                    let mut router = smart_router.lock();
                    router.record_result(&target_addr, false, latency);
                }

                return Err(e).context("Failed to connect");
            }
        };

        let target = format!("{}:{}", target_addr, target_port);

        // Record successful connection through router
        {
            let mut router = smart_router.lock();
            router.record_result(&target, true, connect_latency);
        }

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

        // Record traffic stats
        {
            let mut analyzer = traffic_analyzer.lock();
            analyzer.record_request(RequestInfo {
                timestamp: start_time,
                size: n as u64,
                latency: start_time.elapsed(),
                protocol: "socks5".to_string(),
                success: true,
            });
        }

        let (client_to_server, server_to_client) =
            tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;

        // Record actual bytes transferred
        {
            let mut analyzer = traffic_analyzer.lock();
            analyzer.record_bytes(server_to_client, client_to_server);
        }

        Ok(())
    }
}
