use std::sync::Arc;
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use crate::config::IPPoolConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStrategy {
    Random,
    RoundRobin,
    LeastUsed,
    PerformanceBased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPInfo {
    pub address: String,
    pub port: u16,
    pub country: Option<String>,
    pub isp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddIPRequest {
    pub address: String,
    pub port: u16,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateIPRequest {
    pub address: String,
    pub port: Option<u16>,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPStatsSnapshot {
    pub total_uses: u64,
    pub total_failures: u64,
    pub avg_latency_ms: f64,
    pub enabled: bool,
    pub health_status: HealthStatus,
    pub use_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub latency_ms: f64,
}

#[derive(Debug)]
struct IPStats {
    total_uses: u64,
    total_failures: u64,
    avg_latency: Duration,
    last_failure: Option<Instant>,
}

#[derive(Debug, Clone)]
struct NodeState {
    enabled: bool,
    health_status: HealthStatus,
    use_count: u64,
    success_count: u64,
    failure_count: u64,
    latency: Duration,
    last_used: Instant,
}

impl NodeState {
    fn new() -> Self {
        Self {
            enabled: true,
            health_status: HealthStatus::Unknown,
            use_count: 0,
            success_count: 0,
            failure_count: 0,
            latency: Duration::from_millis(100),
            last_used: Instant::now(),
        }
    }
}

/// Threshold constants for automatic health status updates.
const HEALTH_DEGRADED_FAILURE_RATE: f64 = 0.3;
const HEALTH_UNHEALTHY_FAILURE_RATE: f64 = 0.6;
const HEALTH_MIN_SAMPLES: u64 = 5;

pub struct IPManager {
    ip_pool: Vec<Arc<IPInfo>>,
    ip_stats: DashMap<String, IPStats>,
    node_states: DashMap<String, NodeState>,
    current_index: Mutex<usize>,
    config: IPPoolConfig,
}

impl IPManager {
    pub fn new(config: IPPoolConfig) -> Self {
        let mut ip_pool = Vec::new();
        let ip_stats = DashMap::new();
        let node_states = DashMap::new();

        for ip_config in &config.ips {
            let ip_info = Arc::new(IPInfo {
                address: ip_config.address.clone(),
                port: ip_config.port,
                country: ip_config.country.clone(),
                isp: ip_config.isp.clone(),
            });

            ip_pool.push(ip_info);
            ip_stats.insert(ip_config.address.clone(), IPStats {
                total_uses: 0,
                total_failures: 0,
                avg_latency: Duration::from_millis(100),
                last_failure: None,
            });
            node_states.insert(ip_config.address.clone(), NodeState::new());
        }

        Self { ip_pool, ip_stats, node_states, current_index: Mutex::new(0), config }
    }

    /// Select an IP based on the configured rotation strategy.
    /// Takes `&self` — the only mutable state is `current_index` (Mutex-protected).
    pub fn select_ip(&self) -> Option<Arc<IPInfo>> {
        if self.ip_pool.is_empty() {
            return None;
        }

        let selected = match self.config.strategy.as_str() {
            "random" => self.select_random(),
            "roundrobin" => self.select_round_robin(),
            "leastused" => self.select_least_used(),
            "performance" => self.select_performance_based(),
            _ => self.select_round_robin(),
        };

        Some(selected)
    }

    pub fn get_all_ips(&self) -> Vec<Arc<IPInfo>> {
        self.ip_pool.clone()
    }

    pub fn get_proxy_endpoint(&self) -> Option<String> {
        self.ip_pool.first().map(|ip| format!("{}:{}", ip.address, ip.port))
    }

    pub fn is_empty(&self) -> bool {
        self.ip_pool.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ip_pool.len()
    }

    pub fn get_ip_stats(&self, address: &str) -> Option<IPStatsSnapshot> {
        let stats = self.ip_stats.get(address)?;
        let state = self.node_states.get(address)?;

        Some(IPStatsSnapshot {
            total_uses: stats.total_uses,
            total_failures: stats.total_failures,
            avg_latency_ms: stats.avg_latency.as_secs_f64() * 1000.0,
            enabled: state.enabled,
            health_status: state.health_status,
            use_count: state.use_count,
            success_count: state.success_count,
            failure_count: state.failure_count,
            latency_ms: state.latency.as_secs_f64() * 1000.0,
        })
    }

    pub async fn test_latency(&self, address: &str, port: u16) -> Option<Duration> {
        let target = format!("{}:{}", address, port);
        let start = Instant::now();
        match tokio::net::TcpStream::connect(&target).await {
            Ok(_) => Some(start.elapsed()),
            Err(_) => None,
        }
    }

    pub fn add_node(&mut self, req: AddIPRequest) -> bool {
        if self.ip_pool.iter().any(|ip| ip.address == req.address) {
            return false;
        }

        let ip_info = Arc::new(IPInfo {
            address: req.address.clone(),
            port: req.port,
            country: req.country,
            isp: req.isp,
        });

        self.ip_pool.push(ip_info);
        self.ip_stats.insert(req.address.clone(), IPStats {
            total_uses: 0,
            total_failures: 0,
            avg_latency: Duration::from_millis(100),
            last_failure: None,
        });
        let mut state = NodeState::new();
        if let Some(enabled) = req.enabled {
            state.enabled = enabled;
        }
        self.node_states.insert(req.address, state);

        true
    }

    pub fn remove_node(&mut self, address: &str) -> bool {
        let initial_len = self.ip_pool.len();
        self.ip_pool.retain(|ip| ip.address != address);
        self.ip_stats.remove(address);
        self.node_states.remove(address);
        self.ip_pool.len() < initial_len
    }

    pub fn update_node(&mut self, address: &str, req: UpdateIPRequest) -> bool {
        let idx = match self.ip_pool.iter().position(|ip| ip.address == address) {
            Some(i) => i,
            None => return false,
        };

        if req.port.is_some() || req.country.is_some() || req.isp.is_some() {
            let old = &self.ip_pool[idx];
            self.ip_pool[idx] = Arc::new(IPInfo {
                address: old.address.clone(),
                port: req.port.unwrap_or(old.port),
                country: req.country.or_else(|| old.country.clone()),
                isp: req.isp.or_else(|| old.isp.clone()),
            });
        }

        if let Some(enabled) = req.enabled {
            if let Some(mut state) = self.node_states.get_mut(address) {
                state.enabled = enabled;
            }
        }

        true
    }

    pub fn toggle_node(&mut self, address: &str) -> Option<bool> {
        let mut state = self.node_states.get_mut(address)?;
        state.enabled = !state.enabled;
        Some(state.enabled)
    }

    pub fn get_node(&self, address: &str) -> Option<Arc<IPInfo>> {
        self.ip_pool.iter().find(|ip| ip.address == address).cloned()
    }

    pub fn record_result(&self, ip: &str, success: bool, latency: Duration) {
        if let Some(mut stats) = self.ip_stats.get_mut(ip) {
            stats.total_uses += 1;

            // Running average latency
            let n = stats.total_uses as f64;
            let old_avg = stats.avg_latency.as_secs_f64();
            let new_latency = latency.as_secs_f64();
            stats.avg_latency = Duration::from_secs_f64(
                (old_avg * (n - 1.0) + new_latency) / n
            );

            if !success {
                stats.total_failures += 1;
                stats.last_failure = Some(Instant::now());
            }
        }

        if let Some(mut state) = self.node_states.get_mut(ip) {
            // Always increment use_count regardless of success/failure.
            state.use_count += 1;
            state.last_used = Instant::now();

            if success {
                state.success_count += 1;
                state.latency = latency;
            } else {
                state.failure_count += 1;
            }

            // Auto-update health status based on accumulated results.
            let total = state.success_count + state.failure_count;
            if total >= HEALTH_MIN_SAMPLES {
                let failure_rate = state.failure_count as f64 / total as f64;
                state.health_status = if failure_rate >= HEALTH_UNHEALTHY_FAILURE_RATE {
                    HealthStatus::Unhealthy
                } else if failure_rate >= HEALTH_DEGRADED_FAILURE_RATE {
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Healthy
                };
            }
        }
    }

    // ── Selection strategies ────────────────────────────────────────────────

    /// Predicate: is an IP considered available for selection?
    fn is_available(&self, address: &str) -> bool {
        self.node_states.get(address).map_or(false, |s| {
            s.enabled && !matches!(s.health_status, HealthStatus::Unhealthy)
        })
    }

    fn select_random(&self) -> Arc<IPInfo> {
        let available: Vec<_> = self.ip_pool.iter()
            .filter(|ip| self.is_available(&ip.address))
            .collect();

        if available.is_empty() {
            // Fallback: return any IP (pool is guaranteed non-empty by caller).
            return self.ip_pool[0].clone();
        }

        let idx = rand::random_range(0..available.len());
        available[idx].clone()
    }

    fn select_round_robin(&self) -> Arc<IPInfo> {
        let len = self.ip_pool.len();
        for _ in 0..len {
            let mut current = self.current_index.lock();
            *current = (*current + 1) % len;
            let index = *current;
            drop(current);

            if let Some(ip) = self.ip_pool.get(index) {
                if self.is_available(&ip.address) {
                    return ip.clone();
                }
            }
        }

        // All unhealthy/disabled — return current index anyway.
        self.ip_pool[*self.current_index.lock() % len].clone()
    }

    fn select_least_used(&self) -> Arc<IPInfo> {
        self.ip_pool.iter()
            .filter(|ip| self.is_available(&ip.address))
            .min_by_key(|ip| {
                self.node_states.get(&ip.address).map(|s| s.use_count).unwrap_or(0)
            })
            .unwrap_or(&self.ip_pool[0])
            .clone()
    }

    fn select_performance_based(&self) -> Arc<IPInfo> {
        let available: Vec<_> = self.ip_pool.iter()
            .filter(|ip| self.is_available(&ip.address))
            .collect();

        if available.is_empty() {
            return self.ip_pool[0].clone();
        }

        // Score = success_rate descending, then latency ascending.
        available.iter()
            .min_by(|a, b| {
                let sa = self.node_states.get(&a.address);
                let sb = self.node_states.get(&b.address);

                let rate_a = sa.as_ref().map(|s| {
                    s.success_count as f64 / (s.use_count.max(1)) as f64
                }).unwrap_or(0.0);
                let rate_b = sb.as_ref().map(|s| {
                    s.success_count as f64 / (s.use_count.max(1)) as f64
                }).unwrap_or(0.0);

                // Higher success rate is better → compare b vs a.
                match rate_b.partial_cmp(&rate_a).unwrap_or(std::cmp::Ordering::Equal) {
                    std::cmp::Ordering::Equal => {
                        let lat_a = sa.as_ref().map(|s| s.latency).unwrap_or(Duration::MAX);
                        let lat_b = sb.as_ref().map(|s| s.latency).unwrap_or(Duration::MAX);
                        lat_a.cmp(&lat_b)
                    }
                    other => other,
                }
            })
            .map(|ip| (*ip).clone())
            .unwrap_or_else(|| self.ip_pool[0].clone())
    }
}
