use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::Serialize;
use crate::traffic_analyzer::TrafficAnalyzer;
use crate::ip_manager::IPManager;
use crate::anomaly_detector::AnomalyDetector;

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
            listen_address,
            listen_port,
        }
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
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(socket, &ta, &im, &ad).await {
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
        } else if request_line.starts_with("GET /api/anomalies") {
            Self::get_anomalies(anomaly_detector)
        } else if request_line.starts_with("GET /api/health") {
            Self::health_check()
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
}
