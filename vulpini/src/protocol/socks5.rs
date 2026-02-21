use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Socks5Config;
use crate::traffic_analyzer::{TrafficAnalyzer, RequestInfo};
use crate::behavior_monitor::{BehaviorMonitor, BehaviorRecord, ActionType};
use crate::ip_manager::IPManager;
use crate::smart_router::SmartRouter;

const SOCKS5_VERSION: u8 = 0x05;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

// SOCKS5 REP codes (RFC 1928)
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONN_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Build a minimal SOCKS5 reply with an IPv4 zero bound address.
fn socks5_reply(rep: u8) -> [u8; 10] {
    [0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

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
        Self { config, traffic_analyzer, behavior_monitor, ip_manager, smart_router }
    }

    pub async fn start(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);
        let listener = TcpListener::bind(&addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;

        println!("SOCKS5 server listening on {}", addr);

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
                            println!("[SOCKS5] Connection limit ({}) reached, dropping {}", max_conn, peer_addr);
                            drop(socket);
                            continue;
                        }
                    };

                    let traffic_analyzer = self.traffic_analyzer.clone();
                    let behavior_monitor = self.behavior_monitor.clone();
                    let ip_manager = self.ip_manager.clone();
                    let smart_router = self.smart_router.clone();
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
                            &ip_manager,
                            &smart_router,
                        ).await {
                            println!("[SOCKS5] Connection error: {}", e);
                        }
                    });
                }
                Err(e) => println!("[SOCKS5] Accept error: {}", e),
            }
        }
    }

    /// Connect to an upstream SOCKS5 proxy and forward the client's CONNECT request.
    /// Performs the full SOCKS5 greeting + CONNECT handshake before returning the stream.
    async fn connect_via_upstream(upstream_addr: &str, connect_req: &[u8]) -> Result<TcpStream> {
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream_addr))
            .await
            .context("Upstream connect timed out")?
            .context("Upstream connect failed")?;

        // Greeting: no-auth only
        stream.write_all(&[0x05, 0x01, 0x00]).await.context("Upstream greeting write failed")?;

        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp).await.context("Upstream method response failed")?;
        if method_resp[0] != 0x05 || method_resp[1] != 0x00 {
            anyhow::bail!("Upstream rejected no-auth (method=0x{:02x})", method_resp[1]);
        }

        // Forward the original client CONNECT request as-is
        stream.write_all(connect_req).await.context("Upstream CONNECT send failed")?;

        // Read reply header: VER REP RSV ATYP
        let mut rep_hdr = [0u8; 4];
        stream.read_exact(&mut rep_hdr).await.context("Upstream CONNECT reply read failed")?;
        if rep_hdr[1] != REP_SUCCESS {
            anyhow::bail!("Upstream CONNECT rejected (rep=0x{:02x})", rep_hdr[1]);
        }

        // Drain bound address from upstream reply so stream is ready for data
        match rep_hdr[3] {
            0x01 => {
                // IPv4 (4 bytes) + port (2 bytes)
                let mut discard = [0u8; 6];
                stream.read_exact(&mut discard).await.context("Upstream reply IPv4 drain failed")?;
            }
            0x03 => {
                // domain: length byte, then domain bytes, then port (2 bytes)
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let mut discard = vec![0u8; len_buf[0] as usize + 2];
                stream.read_exact(&mut discard).await.context("Upstream reply domain drain failed")?;
            }
            0x04 => {
                // IPv6 (16 bytes) + port (2 bytes)
                let mut discard = [0u8; 18];
                stream.read_exact(&mut discard).await.context("Upstream reply IPv6 drain failed")?;
            }
            other => {
                anyhow::bail!("Upstream replied with unknown ATYP: 0x{:02x}", other);
            }
        }

        Ok(stream)
    }

    async fn handle_connection(
        mut socket: TcpStream,
        peer_addr: String,
        start_time: Instant,
        config: Socks5Config,
        traffic_analyzer: &Arc<parking_lot::Mutex<TrafficAnalyzer>>,
        behavior_monitor: &Arc<BehaviorMonitor>,
        ip_manager: &Arc<parking_lot::Mutex<IPManager>>,
        smart_router: &Arc<parking_lot::Mutex<SmartRouter>>,
    ) -> Result<()> {
        let mut buf = [0u8; 262];

        // ── Greeting ────────────────────────────────────────────────────────────
        let n = socket.read(&mut buf).await.context("Failed to read greeting")?;
        if n < 3 || buf[0] != SOCKS5_VERSION {
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

            // ── Username/Password subnegotiation (RFC 1929) ──────────────────
            let n = socket.read(&mut buf).await.context("Failed to read auth")?;
            if n < 3 || buf[0] != 0x01 {
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }

            let ulen = buf[1] as usize;
            if 2 + ulen + 1 > n {
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
            let plen = buf[2 + ulen] as usize;
            if 3 + ulen + plen > n {
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }

            let username = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
            let password = String::from_utf8_lossy(&buf[3 + ulen..3 + ulen + plen]).to_string();

            let auth_ok = match (expected_username, expected_password) {
                (Some(eu), Some(ep)) => username == eu && password == ep,
                (Some(eu), None) => username == eu,
                (None, Some(ep)) => password == ep,
                _ => true,
            };

            if auth_ok {
                socket.write_all(&[0x01, 0x00]).await?;
            } else {
                println!("[SOCKS5] Auth failed for user: {}", username);
                socket.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
        } else {
            socket.write_all(&[SOCKS5_VERSION, 0x00]).await?;
        }

        // ── CONNECT Request ──────────────────────────────────────────────────
        let n = socket.read(&mut buf).await.context("Failed to read CONNECT request")?;
        if n < 4 || buf[0] != SOCKS5_VERSION {
            return Ok(());
        }

        if buf[1] != 0x01 {
            socket.write_all(&socks5_reply(REP_CMD_NOT_SUPPORTED)).await?;
            return Ok(());
        }

        let atyp = buf[3];
        let (target_addr, target_port) = match atyp {
            0x01 => {
                // IPv4: 4-byte address + 2-byte port
                if n < 10 { return Ok(()); }
                let addr = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                (addr, port)
            }
            0x03 => {
                // Domain: 1-byte length, domain bytes, 2-byte port
                if n < 5 { return Ok(()); }
                let domain_len = buf[4] as usize;
                if n < 5 + domain_len + 2 { return Ok(()); }
                let addr = String::from_utf8_lossy(&buf[5..5 + domain_len]).to_string();
                let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
                (addr, port)
            }
            0x04 => {
                // IPv6: 16-byte address + 2-byte port
                if n < 22 { return Ok(()); }
                let ipv6 = std::net::Ipv6Addr::from([
                    buf[4],  buf[5],  buf[6],  buf[7],
                    buf[8],  buf[9],  buf[10], buf[11],
                    buf[12], buf[13], buf[14], buf[15],
                    buf[16], buf[17], buf[18], buf[19],
                ]);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                (format!("[{}]", ipv6), port)
            }
            _ => {
                socket.write_all(&socks5_reply(REP_ATYP_NOT_SUPPORTED)).await?;
                return Ok(());
            }
        };

        let upstream_addr = {
            let manager = ip_manager.lock();
            if manager.is_empty() { None } else { manager.get_proxy_endpoint() }
        };

        let target = format!("{}:{}", target_addr, target_port);
        let connect_start = Instant::now();

        let mut upstream_stream = if let Some(ref upstream) = upstream_addr {
            match Self::connect_via_upstream(upstream, &buf[..n]).await {
                Ok(s) => s,
                Err(e) => {
                    socket.write_all(&socks5_reply(REP_GENERAL_FAILURE)).await?;
                    println!("[SOCKS5] Upstream connect failed ({} via {}): {}", target, upstream, e);
                    let latency = connect_start.elapsed();
                    traffic_analyzer.lock().record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency,
                        protocol: "socks5".to_string(),
                        success: false,
                    });
                    smart_router.lock().record_result(&target, false, latency);
                    return Ok(());
                }
            }
        } else {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    socket.write_all(&socks5_reply(REP_CONN_REFUSED)).await?;
                    println!("[SOCKS5] Connect failed to {}: {}", target, e);
                    let latency = connect_start.elapsed();
                    traffic_analyzer.lock().record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency,
                        protocol: "socks5".to_string(),
                        success: false,
                    });
                    smart_router.lock().record_result(&target, false, latency);
                    return Ok(());
                }
                Err(_) => {
                    socket.write_all(&socks5_reply(REP_HOST_UNREACHABLE)).await?;
                    println!("[SOCKS5] Connect timeout to {}", target);
                    traffic_analyzer.lock().record_request(RequestInfo {
                        timestamp: start_time,
                        size: n as u64,
                        latency: CONNECT_TIMEOUT,
                        protocol: "socks5".to_string(),
                        success: false,
                    });
                    smart_router.lock().record_result(&target, false, CONNECT_TIMEOUT);
                    return Ok(());
                }
            }
        };

        let connect_latency = connect_start.elapsed();

        // Send success reply
        socket.write_all(&socks5_reply(REP_SUCCESS)).await?;

        // Record metrics
        smart_router.lock().record_result(&target, true, connect_latency);
        behavior_monitor.record_action(&peer_addr, &BehaviorRecord {
            session_id: uuid::Uuid::new_v4().to_string(),
            timestamp: start_time,
            action_type: ActionType::Connect,
            duration: connect_latency,
            target: target.clone(),
            success: true,
        });
        {
            let mut analyzer = traffic_analyzer.lock();
            analyzer.record_request(RequestInfo {
                timestamp: start_time,
                size: n as u64,
                latency: connect_latency,
                protocol: "socks5".to_string(),
                success: true,
            });
        }

        let (client_to_server, server_to_client) =
            tokio::io::copy_bidirectional(&mut socket, &mut upstream_stream).await?;

        traffic_analyzer.lock().record_bytes(server_to_client, client_to_server);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_reply_success() {
        let reply = socks5_reply(REP_SUCCESS);
        assert_eq!(reply[0], 0x05); // version
        assert_eq!(reply[1], 0x00); // success
        assert_eq!(reply[2], 0x00); // reserved
        assert_eq!(reply[3], 0x01); // IPv4 address type
        assert_eq!(reply.len(), 10);
    }

    #[test]
    fn test_socks5_reply_general_failure() {
        let reply = socks5_reply(REP_GENERAL_FAILURE);
        assert_eq!(reply[1], 0x01);
    }

    #[test]
    fn test_socks5_reply_host_unreachable() {
        let reply = socks5_reply(REP_HOST_UNREACHABLE);
        assert_eq!(reply[1], 0x04);
    }

    #[test]
    fn test_socks5_reply_conn_refused() {
        let reply = socks5_reply(REP_CONN_REFUSED);
        assert_eq!(reply[1], 0x05);
    }

    #[test]
    fn test_socks5_reply_cmd_not_supported() {
        let reply = socks5_reply(REP_CMD_NOT_SUPPORTED);
        assert_eq!(reply[1], 0x07);
    }

    #[test]
    fn test_socks5_reply_atyp_not_supported() {
        let reply = socks5_reply(REP_ATYP_NOT_SUPPORTED);
        assert_eq!(reply[1], 0x08);
    }

    #[test]
    fn test_socks5_reply_zero_bound_address() {
        let reply = socks5_reply(REP_SUCCESS);
        // Bound address should be 0.0.0.0:0
        assert_eq!(&reply[4..8], &[0x00, 0x00, 0x00, 0x00]); // IP
        assert_eq!(&reply[8..10], &[0x00, 0x00]); // port
    }

    #[test]
    fn test_socks5_version_constant() {
        assert_eq!(SOCKS5_VERSION, 0x05);
    }

    #[test]
    fn test_connect_timeout_constant() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(15));
    }
}
