use std::sync::Arc;
use std::time::Instant;
use parking_lot::Mutex;
use axum::{
    Router,
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use serde::Serialize;
use tower_http::cors::CorsLayer;

use crate::traffic_analyzer::TrafficAnalyzer;
use crate::ip_manager::{IPManager, AddIPRequest, UpdateIPRequest};
use crate::anomaly_detector::AnomalyDetector;
use crate::config::ConfigManager;

// ── Shared application state ────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
    pub ip_manager: Arc<Mutex<IPManager>>,
    pub anomaly_detector: Arc<Mutex<AnomalyDetector>>,
    pub config_manager: Arc<Mutex<ConfigManager>>,
    pub start_time: Instant,
}

// ── Response types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ApiOk<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize)]
struct ApiErr {
    success: bool,
    error: String,
}

fn ok<T: Serialize>(data: T) -> Json<ApiOk<T>> {
    Json(ApiOk { success: true, data: Some(data), message: None })
}

fn ok_msg(msg: impl Into<String>) -> Json<ApiOk<()>> {
    Json(ApiOk { success: true, data: None, message: Some(msg.into()) })
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiErr>) {
    (status, Json(ApiErr { success: false, error: msg.into() }))
}

// ── Router ──────────────────────────────────────────────────────────────────

pub fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/stats", get(get_stats))
        .route("/api/ips", get(get_ips).post(add_ip))
        .route("/api/ips/test-all", post(test_all_ips))
        .route("/api/ips/{address}", put(update_ip).patch(toggle_ip).delete(delete_ip))
        .route("/api/anomalies", get(get_anomalies))
        .route("/api/config/reload", post(reload_config))
        .route("/pac", get(get_pac))
        .route("/proxy.pac", get(get_pac))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn health() -> Json<ApiOk<HealthData>> {
    ok(HealthData { status: "healthy".into() })
}

#[derive(Serialize)]
struct HealthData {
    status: String,
}

// GET /api/stats

#[derive(Serialize)]
struct StatsData {
    total_requests: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
    active_connections: u32,
    requests_per_second: f64,
    bytes_per_second: f64,
    avg_latency_ms: f64,
    error_rate: f64,
}

async fn get_stats(State(state): State<AppState>) -> Json<ApiOk<StatsData>> {
    let stats = state.traffic_analyzer.lock().get_stats().clone();
    ok(StatsData {
        total_requests: stats.total_requests,
        total_bytes_in: stats.total_bytes_in,
        total_bytes_out: stats.total_bytes_out,
        active_connections: stats.active_connections,
        requests_per_second: stats.requests_per_second,
        bytes_per_second: stats.bytes_per_second,
        avg_latency_ms: stats.avg_latency.as_secs_f64() * 1000.0,
        error_rate: stats.error_rate,
    })
}

// GET /api/ips

#[derive(Serialize)]
struct IpListData {
    ips: Vec<IpEntry>,
    total: usize,
}

#[derive(Serialize)]
struct IpEntry {
    address: String,
    port: u16,
    country: Option<String>,
    isp: Option<String>,
    latency_ms: f64,
    avg_latency_ms: f64,
    status: String,
    enabled: bool,
    total_uses: u64,
    success_count: u64,
    failure_count: u64,
    use_count: u64,
}

async fn get_ips(State(state): State<AppState>) -> Json<ApiOk<IpListData>> {
    let manager = state.ip_manager.lock();
    let ips = manager.get_all_ips();

    let entries: Vec<IpEntry> = ips.iter().map(|ip| {
        let stats = manager.get_ip_stats(&ip.address);
        IpEntry {
            address: ip.address.clone(),
            port: ip.port,
            country: ip.country.clone(),
            isp: ip.isp.clone(),
            latency_ms: stats.as_ref().map(|s| s.latency_ms).unwrap_or(0.0),
            avg_latency_ms: stats.as_ref().map(|s| s.avg_latency_ms).unwrap_or(0.0),
            status: stats.as_ref()
                .map(|s| format!("{:?}", s.health_status).to_lowercase())
                .unwrap_or_else(|| "unknown".into()),
            enabled: stats.as_ref().map(|s| s.enabled).unwrap_or(true),
            total_uses: stats.as_ref().map(|s| s.total_uses).unwrap_or(0),
            success_count: stats.as_ref().map(|s| s.success_count).unwrap_or(0),
            failure_count: stats.as_ref().map(|s| s.failure_count).unwrap_or(0),
            use_count: stats.as_ref().map(|s| s.use_count).unwrap_or(0),
        }
    }).collect();

    let total = entries.len();
    ok(IpListData { ips: entries, total })
}

// POST /api/ips

#[derive(Serialize)]
struct AddIpResult {
    address: String,
    port: u16,
    country: Option<String>,
    isp: Option<String>,
    enabled: bool,
}

async fn add_ip(
    State(state): State<AppState>,
    Json(req): Json<AddIPRequest>,
) -> Result<Json<ApiOk<AddIpResult>>, (StatusCode, Json<ApiErr>)> {
    let mut manager = state.ip_manager.lock();
    if manager.add_node(req.clone()) {
        Ok(ok(AddIpResult {
            address: req.address,
            port: req.port,
            country: req.country,
            isp: req.isp,
            enabled: req.enabled.unwrap_or(true),
        }))
    } else {
        Err(err(StatusCode::CONFLICT, "Node already exists"))
    }
}

// PUT /api/ips/{address}

async fn update_ip(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Json(req): Json<UpdateIPRequest>,
) -> Result<Json<ApiOk<()>>, (StatusCode, Json<ApiErr>)> {
    let mut manager = state.ip_manager.lock();
    if manager.update_node(&address, req) {
        Ok(ok_msg(format!("Node {} updated", address)))
    } else {
        Err(err(StatusCode::NOT_FOUND, "Node not found"))
    }
}

// PATCH /api/ips/{address}

#[derive(Serialize)]
struct ToggleResult {
    enabled: bool,
}

async fn toggle_ip(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<ApiOk<ToggleResult>>, (StatusCode, Json<ApiErr>)> {
    let mut manager = state.ip_manager.lock();
    match manager.toggle_node(&address) {
        Some(enabled) => Ok(ok(ToggleResult { enabled })),
        None => Err(err(StatusCode::NOT_FOUND, "Node not found")),
    }
}

// DELETE /api/ips/{address}

async fn delete_ip(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<ApiOk<()>>, (StatusCode, Json<ApiErr>)> {
    let mut manager = state.ip_manager.lock();
    if manager.remove_node(&address) {
        Ok(ok_msg(format!("IP {} deleted", address)))
    } else {
        Err(err(StatusCode::NOT_FOUND, "Node not found"))
    }
}

// POST /api/ips/test-all

#[derive(Serialize)]
struct TestResult {
    address: String,
    port: u16,
    latency_ms: f64,
    success: bool,
}

async fn test_all_ips(State(state): State<AppState>) -> Json<ApiOk<Vec<TestResult>>> {
    let ips = {
        let manager = state.ip_manager.lock();
        manager.get_all_ips()
    };

    let mut results = Vec::with_capacity(ips.len());
    for ip in &ips {
        let target = format!("{}:{}", ip.address, ip.port);
        let start = Instant::now();
        let result = tokio::net::TcpStream::connect(&target).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        results.push(TestResult {
            address: ip.address.clone(),
            port: ip.port,
            latency_ms,
            success: result.is_ok(),
        });
    }

    ok(results)
}

// GET /api/anomalies

#[derive(Serialize)]
struct AnomalyEntry {
    id: String,
    timestamp: u64,
    anomaly_type: String,
    value: f64,
    threshold: f64,
    description: String,
    severity: String,
}

async fn get_anomalies(State(state): State<AppState>) -> Json<ApiOk<Vec<AnomalyEntry>>> {
    let detector = state.anomaly_detector.lock();
    let events = detector.get_event_history();

    let entries: Vec<AnomalyEntry> = events.iter().map(|e| {
        AnomalyEntry {
            id: e.id.clone(),
            timestamp: e.timestamp.elapsed().as_secs(),
            anomaly_type: format!("{:?}", e.anomaly_type).to_lowercase(),
            value: e.value,
            threshold: e.threshold,
            description: e.description.clone(),
            severity: format!("{:?}", e.severity).to_lowercase(),
        }
    }).collect();

    ok(entries)
}

// POST /api/config/reload

async fn reload_config(
    State(state): State<AppState>,
) -> Result<Json<ApiOk<()>>, (StatusCode, Json<ApiErr>)> {
    let mut manager = state.config_manager.lock();
    match manager.reload() {
        Ok(_) => Ok(ok_msg("Configuration reloaded")),
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to reload config: {}", e),
        )),
    }
}

// GET /pac, GET /proxy.pac

async fn get_pac(State(state): State<AppState>) -> impl IntoResponse {
    let manager = state.ip_manager.lock();
    let socks5_addr = manager
        .get_proxy_endpoint()
        .unwrap_or_else(|| "127.0.0.1:1080".into());

    let pac = format!(
        r#"// Proxy Auto-Config file for Vulpini

function FindProxyForURL(url, host) {{
    if (isPlainHostName(host) || shExpMatch(host, "*.local")) {{
        return "DIRECT";
    }}
    if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.255.255.0")) {{
        return "DIRECT";
    }}
    return "SOCKS5 {0}";
}}
"#,
        socks5_addr
    );

    (
        StatusCode::OK,
        [("content-type", "application/x-ns-proxy-autoconfig")],
        pac,
    )
}
