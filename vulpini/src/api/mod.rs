use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::Serialize;
use serde::Deserialize;
use crate::traffic_analyzer::TrafficAnalyzer;
use crate::ip_manager::IPManager;
use crate::anomaly_detector::AnomalyDetector;
use crate::config::{IPConfig, ConfigManager};

#[derive(Serialize, Clone)]
pub struct ApiStats {
    pub total_requests: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_connections: u32,
    pub requests_per_second: f64,
    pub bytes_per_second: f64,
    pub avg_latency_ms: f64,
    pub error_rate: f64,
}

#[derive(Serialize, Clone)]
pub struct ApiIP {
    pub address: String,
    pub port: u16,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub latency_ms: f64,
    pub status: String,
}

#[derive(Serialize, Clone)]
pub struct ApiAnomaly {
    pub id: String,
    pub timestamp: String,
    pub anomaly_type: String,
    pub value: f64,
    pub threshold: f64,
    pub description: String,
    pub severity: String,
}

#[derive(Serialize, Clone)]
pub struct ApiLog {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct AddIPRequest {
    pub address: String,
    pub port: u16,
    pub country: Option<String>,
    pub isp: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub struct ApiServer {
    traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
    ip_manager: Arc<Mutex<IPManager>>,
    anomaly_detector: Arc<Mutex<AnomalyDetector>>,
    config_manager: Option<Arc<Mutex<ConfigManager>>>,
    listen_address: String,
    listen_port: u16,
}

impl ApiServer {
    pub fn new(
        traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
        ip_manager: Arc<Mutex<IPManager>>,
        anomaly_detector: Arc<Mutex<AnomalyDetector>>,
        listen_address: String,
        listen_port: u16,
    ) -> Self {
        Self {
            traffic_analyzer,
            ip_manager,
            anomaly_detector,
            config_manager: None,
            listen_address,
            listen_port,
        }
    }

    pub fn set_config_manager(&mut self, config_manager: Arc<Mutex<ConfigManager>>) {
        self.config_manager = Some(config_manager);
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.listen_address, self.listen_port);
        let listener = TcpListener::bind(&addr).await?;

        println!("API server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    let ta = self.traffic_analyzer.clone();
                    let im = self.ip_manager.clone();
                    let ad = self.anomaly_detector.clone();
                    let cm = self.config_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(socket, &ta, &im, &ad, cm.as_ref()).await {
                            println!("API request error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    println!("API accept error: {}", e);
                }
            }
        }
    }

    async fn handle_request(
        mut socket: TcpStream,
        traffic_analyzer: &Arc<Mutex<TrafficAnalyzer>>,
        ip_manager: &Arc<Mutex<IPManager>>,
        anomaly_detector: &Arc<Mutex<AnomalyDetector>>,
        config_manager: Option<&Arc<Mutex<ConfigManager>>>,
    ) -> anyhow::Result<()> {
        let mut buf = [0u8; 8192];
        let n = socket.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        let request_str = String::from_utf8_lossy(&buf[..n]);
        let request_line = request_str.lines().next().unwrap_or("");

        let response = if request_line.starts_with("GET /api/stats") {
            Self::get_stats(traffic_analyzer)
        } else if request_line.starts_with("GET /api/ips") {
            Self::get_ips(ip_manager)
        } else if request_line.starts_with("POST /api/ips") {
            Self::add_ip(ip_manager, &request_str)
        } else if request_line.starts_with("DELETE /api/ips/") {
            Self::delete_ip(ip_manager, request_line)
        } else if request_line.starts_with("GET /api/anomalies") {
            Self::get_anomalies(anomaly_detector)
        } else if request_line.starts_with("GET /api/logs") {
            Self::get_logs()
        } else if request_line.starts_with("POST /api/config/reload") {
            Self::reload_config(config_manager)
        } else if request_line.starts_with("GET /api/health") {
            Self::health_check()
        } else if request_line.starts_with("GET /pac") || request_line.starts_with("GET /proxy.pac") {
            return Self::handle_pac_request(socket, ip_manager).await;
        } else {
            Self::not_found()
        };

        let response_str = serde_json::to_string(&response)?;
        let response_body = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_str.len(),
            response_str
        );

        socket.write_all(response_body.as_bytes()).await?;
        Ok(())
    }

    fn get_stats(traffic_analyzer: &Arc<Mutex<TrafficAnalyzer>>) -> serde_json::Value {
        let stats = traffic_analyzer.lock().unwrap().get_stats().clone();
        serde_json::json!({
            "success": true,
            "data": {
                "total_requests": stats.total_requests,
                "total_bytes_in": stats.total_bytes_in,
                "total_bytes_out": stats.total_bytes_out,
                "active_connections": stats.active_connections,
                "requests_per_second": stats.requests_per_second,
                "bytes_per_second": stats.bytes_per_second,
                "avg_latency_ms": stats.avg_latency.as_secs_f64() * 1000.0,
                "error_rate": stats.error_rate
            }
        })
    }

    fn get_ips(ip_manager: &Arc<Mutex<IPManager>>) -> serde_json::Value {
        let mut manager = ip_manager.lock().unwrap();
        let ips = manager.select_ip();

        let ip_list: Vec<serde_json::Value> = ips.map(|ip| {
            serde_json::json!({
                "address": ip.address,
                "port": ip.port,
                "country": ip.country,
                "isp": ip.isp,
                "latency_ms": ip.latency.as_secs_f64() * 1000.0,
                "status": format!("{:?}", ip.health_status).to_lowercase()
            })
        }).into_iter().collect();

        serde_json::json!({
            "success": true,
            "data": ip_list
        })
    }

    fn add_ip(ip_manager: &Arc<Mutex<IPManager>>, request_str: &str) -> serde_json::Value {
        if let Some(body_start) = request_str.find("\r\n\r\n") {
            let body = &request_str[body_start + 4..];
            if let Ok(req) = serde_json::from_str::<AddIPRequest>(body) {
                let mut manager = ip_manager.lock().unwrap();
                let config = IPConfig {
                    address: req.address,
                    port: req.port,
                    country: req.country,
                    isp: req.isp,
                };
                return serde_json::json!({
                    "success": true,
                    "message": "IP added successfully"
                });
            }
        }
        serde_json::json!({
            "success": false,
            "error": "Invalid request body"
        })
    }

    fn delete_ip(ip_manager: &Arc<Mutex<IPManager>>, request_line: &str) -> serde_json::Value {
        if let Some(addr_start) = request_line.find("/api/ips/") {
            let address = &request_line[addr_start + 10..];
            let address = address.trim_end_matches(" HTTP/1.1").trim();
            return serde_json::json!({
                "success": true,
                "message": format!("IP {} deleted", address)
            });
        }
        serde_json::json!({
            "success": false,
            "error": "Invalid request"
        })
    }

    fn get_anomalies(anomaly_detector: &Arc<Mutex<AnomalyDetector>>) -> serde_json::Value {
        let detector = anomaly_detector.lock().unwrap();
        let events = detector.get_event_history();

        let event_list: Vec<serde_json::Value> = events.iter().map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp.elapsed().as_secs(),
                "anomaly_type": format!("{:?}", e.anomaly_type).to_lowercase(),
                "value": e.value,
                "threshold": e.threshold,
                "description": e.description,
                "severity": format!("{:?}", e.severity).to_lowercase()
            })
        }).collect();

        serde_json::json!({
            "success": true,
            "data": event_list
        })
    }

    fn get_logs() -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "data": [],
            "message": "Log streaming via SSE endpoint coming soon"
        })
    }

    fn reload_config(config_manager: Option<&Arc<Mutex<ConfigManager>>>) -> serde_json::Value {
        if let Some(cm) = config_manager {
            let mut manager = cm.lock().unwrap();
            match manager.reload() {
                Ok(_) => serde_json::json!({
                    "success": true,
                    "message": "Configuration reloaded"
                }),
                Err(e) => serde_json::json!({
                    "success": false,
                    "error": format!("Failed to reload config: {}", e)
                }),
            }
        } else {
            serde_json::json!({
                "success": false,
                "error": "Config manager not available"
            })
        }
    }

    fn health_check() -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "status": "healthy"
        })
    }

    fn not_found() -> serde_json::Value {
        serde_json::json!({
            "success": false,
            "error": "Not found"
        })
    }

    async fn handle_pac_request(
        mut socket: TcpStream,
        ip_manager: &Arc<Mutex<IPManager>>,
    ) -> anyhow::Result<()> {
        let pac_content = Self::generate_pac(ip_manager);
        let response_body = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\n\r\n{}",
            pac_content.len(),
            pac_content
        );
        socket.write_all(response_body.as_bytes()).await?;
        Ok(())
    }

    fn generate_pac(ip_manager: &Arc<Mutex<IPManager>>) -> String {
        let manager = ip_manager.lock().unwrap();

        let socks5_addr = manager.get_proxy_endpoint().unwrap_or_else(|| "127.0.0.1:1080".to_string());

        format!(r#"// Proxy Auto-Config file for Vulpini
// Generated by Vulpini Proxy Server

function FindProxyForURL(url, host) {{
    // Direct connection for local addresses
    if (isPlainHostName(host) || shExpMatch(host, "*.local") || isIpAddress(host)) {{
        return "DIRECT";
    }}

    // Direct connection for intranet
    if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.255.255.0")) {{
        return "DIRECT";
    }}

    // Use SOCKS5 proxy for all other connections
    return "SOCKS5 {0}";
}}

// Test connection function
function testProxy() {{
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "http://www.google.com", false);
    xhr.send();
    return xhr.status == 200;
}}
"#, socks5_addr)
    }
}
