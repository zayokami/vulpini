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
    pub enabled: bool,
    pub health_status: HealthStatus,
    pub use_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub latency: Duration,
    pub last_used: Instant,
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

        Self {
            ip_pool,
            ip_stats,
            node_states,
            current_index: Mutex::new(0),
            config,
        }
    }

    pub fn select_ip(&mut self) -> Option<Arc<IPInfo>> {
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

    /// Get all IPs in the pool
    pub fn get_all_ips(&self) -> Vec<Arc<IPInfo>> {
        self.ip_pool.clone()
    }

    /// Get the first available proxy endpoint as string (address:port)
    pub fn get_proxy_endpoint(&self) -> Option<String> {
        self.ip_pool.first().map(|ip| format!("{}:{}", ip.address, ip.port))
    }

    /// Check if IP pool is empty
    pub fn is_empty(&self) -> bool {
        self.ip_pool.is_empty()
    }

    /// Get total number of IPs
    pub fn len(&self) -> usize {
        self.ip_pool.len()
    }

    /// Get stats for a specific IP
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

    /// Test latency to a specific IP
    pub async fn test_latency(&self, address: &str, port: u16) -> Option<Duration> {
        let target = format!("{}:{}", address, port);
        let start = Instant::now();

        match tokio::net::TcpStream::connect(&target).await {
            Ok(_) => {
                let latency = start.elapsed();
                Some(latency)
            }
            Err(_) => None,
        }
    }

    /// Add a new node
    pub fn add_node(&mut self, req: AddIPRequest) -> bool {
        // Check if already exists
        if self.ip_pool.iter().any(|ip| ip.address == req.address) {
            return false;
        }

        let ip_info = Arc::new(IPInfo {
            address: req.address.clone(),
            port: req.port,
            country: req.country,
            isp: req.isp,
        });

        self.ip_pool.push(ip_info.clone());
        self.ip_stats.insert(req.address.clone(), IPStats {
            total_uses: 0,
            total_failures: 0,
            avg_latency: Duration::from_millis(100),
            last_failure: None,
        });
        self.node_states.insert(req.address, NodeState::new());

        true
    }

    /// Remove a node
    pub fn remove_node(&mut self, address: &str) -> bool {
        let initial_len = self.ip_pool.len();
        self.ip_pool.retain(|ip| ip.address != address);
        self.ip_stats.remove(address);
        self.node_states.remove(address);

        self.ip_pool.len() < initial_len
    }

    /// Update a node
    pub fn update_node(&mut self, address: &str, req: UpdateIPRequest) -> bool {
        let idx = match self.ip_pool.iter().position(|ip| ip.address == address) {
            Some(i) => i,
            None => return false,
        };

        // Update IPInfo if any field changed
        if req.port.is_some() || req.country.is_some() || req.isp.is_some() {
            let old = &self.ip_pool[idx];
            self.ip_pool[idx] = Arc::new(IPInfo {
                address: old.address.clone(),
                port: req.port.unwrap_or(old.port),
                country: req.country.or_else(|| old.country.clone()),
                isp: req.isp.or_else(|| old.isp.clone()),
            });
        }

        // Update enabled status
        if let Some(enabled) = req.enabled {
            if let Some(mut state) = self.node_states.get_mut(address) {
                state.enabled = enabled;
            }
        }

        true
    }

    /// Toggle node enabled status
    pub fn toggle_node(&mut self, address: &str) -> Option<bool> {
        if let Some(mut state) = self.node_states.get_mut(address) {
            state.enabled = !state.enabled;
            return Some(state.enabled);
        }
        None
    }

    /// Get node by address
    pub fn get_node(&self, address: &str) -> Option<Arc<IPInfo>> {
        self.ip_pool.iter().find(|ip| ip.address == address).cloned()
    }

    pub fn record_result(&self, ip: &str, success: bool, latency: Duration) {
        if let Some(mut stats) = self.ip_stats.get_mut(ip) {
            stats.total_uses += 1;

            let n = stats.total_uses as f64;
            let old_avg = stats.avg_latency.as_secs_f64();
            let new_latency = latency.as_secs_f64();
            stats.avg_latency = Duration::from_secs_f64(
                (old_avg * (n - 1.0) + new_latency) / n
            );

            if success {
                if let Some(mut state) = self.node_states.get_mut(ip) {
                    state.success_count += 1;
                    state.use_count += 1;
                    state.latency = latency;
                    state.last_used = Instant::now();
                }
            } else {
                stats.total_failures += 1;
                stats.last_failure = Some(Instant::now());
                if let Some(mut state) = self.node_states.get_mut(ip) {
                    state.failure_count += 1;
                }
            }
        }
    }

    fn select_random(&self) -> Arc<IPInfo> {
        let healthy_ips: Vec<_> = self.ip_pool
            .iter()
            .filter(|ip| {
                if let Some(state) = self.node_states.get(&ip.address) {
                    state.enabled && matches!(state.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown)
                } else {
                    false
                }
            })
            .collect();

        if healthy_ips.is_empty() {
            return self.ip_pool[0].clone();
        }

        let idx = rand::random_range(0..healthy_ips.len());
        healthy_ips[idx].clone()
    }

    fn select_round_robin(&self) -> Arc<IPInfo> {
        for _ in 0..self.ip_pool.len() {
            let mut current = self.current_index.lock();
            *current = (*current + 1) % self.ip_pool.len();
            let index = *current;
            drop(current);

            if let Some(ip) = self.ip_pool.get(index) {
                if let Some(state) = self.node_states.get(&ip.address) {
                    if state.enabled && matches!(state.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown) {
                        return ip.clone();
                    }
                }
            }
        }

        self.ip_pool[0].clone()
    }

    fn select_least_used(&self) -> Arc<IPInfo> {
        self.ip_pool
            .iter()
            .filter(|ip| {
                if let Some(state) = self.node_states.get(&ip.address) {
                    state.enabled && matches!(state.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown)
                } else {
                    false
                }
            })
            .min_by_key(|ip| {
                self.node_states.get(&ip.address)
                    .map(|s| s.use_count)
                    .unwrap_or(0)
            })
            .unwrap_or(&self.ip_pool[0])
            .clone()
    }

    fn select_performance_based(&self) -> Arc<IPInfo> {
        let healthy_ips: Vec<_> = self.ip_pool
            .iter()
            .filter(|ip| {
                if let Some(state) = self.node_states.get(&ip.address) {
                    state.enabled && matches!(state.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown)
                } else {
                    false
                }
            })
            .collect();

        if healthy_ips.is_empty() {
            return self.ip_pool[0].clone();
        }

        match healthy_ips.iter().min_by(|a, b| {
            let state_a = self.node_states.get(&a.address);
            let state_b = self.node_states.get(&b.address);

            let success_rate_a = state_a.as_ref()
                .map(|s| s.success_count as f64 / (s.success_count + s.failure_count + 1) as f64)
                .unwrap_or(0.0);
            let success_rate_b = state_b.as_ref()
                .map(|s| s.success_count as f64 / (s.success_count + s.failure_count + 1) as f64)
                .unwrap_or(0.0);

            let latency_a = state_a.as_ref().map(|s| s.latency).unwrap_or(Duration::from_millis(100));
            let latency_b = state_b.as_ref().map(|s| s.latency).unwrap_or(Duration::from_millis(100));

            let rate_cmp = success_rate_b.partial_cmp(&success_rate_a).unwrap_or(std::cmp::Ordering::Equal);

            match rate_cmp {
                std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
                std::cmp::Ordering::Less => std::cmp::Ordering::Less,
                std::cmp::Ordering::Equal => latency_a.cmp(&latency_b),
            }
        }) {
            Some(best) => (*best).clone(),
            None => self.ip_pool[0].clone(),
        }
    }
}
