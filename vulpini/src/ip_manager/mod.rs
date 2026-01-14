use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use crate::config::IPPoolConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStrategy {
    Random,
    RoundRobin,
    LeastUsed,
    PerformanceBased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct IPInfo {
    pub address: String,
    pub port: u16,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub latency: Duration,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_used: Instant,
    pub use_count: u64,
    pub health_status: HealthStatus,
}

pub struct IPManager {
    ip_pool: Vec<Arc<IPInfo>>,
    ip_stats: DashMap<String, IPStats>,
    current_index: Mutex<usize>,
    config: IPPoolConfig,
}

#[derive(Debug)]
struct IPStats {
    total_uses: u64,
    total_failures: u64,
    avg_latency: Duration,
    last_failure: Option<Instant>,
}

impl IPManager {
    pub fn new(config: IPPoolConfig) -> Self {
        let mut ip_pool = Vec::new();
        let ip_stats = DashMap::new();
        
        for ip_config in &config.ips {
            let ip_info = Arc::new(IPInfo {
                address: ip_config.address.clone(),
                port: ip_config.port,
                country: ip_config.country.clone(),
                isp: ip_config.isp.clone(),
                latency: Duration::from_millis(100),
                success_count: 0,
                failure_count: 0,
                last_used: Instant::now(),
                use_count: 0,
                health_status: HealthStatus::Unknown,
            });
            
            ip_pool.push(ip_info);
            ip_stats.insert(ip_config.address.clone(), IPStats {
                total_uses: 0,
                total_failures: 0,
                avg_latency: Duration::from_millis(100),
                last_failure: None,
            });
        }
        
        Self {
            ip_pool,
            ip_stats,
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
                if let Some(ip_info) = self.ip_pool.iter().find(|i| i.address == ip) {
                    let _ = ip_info.success_count.checked_add(1);
                    let _ = ip_info.latency.checked_add(latency);
                }
            } else {
                stats.total_failures += 1;
                stats.last_failure = Some(Instant::now());
            }
        }
    }

    fn select_random(&self) -> Arc<IPInfo> {
        let healthy_ips: Vec<_> = self.ip_pool
            .iter()
            .filter(|ip| matches!(ip.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown))
            .collect();
        
        if healthy_ips.is_empty() {
            return self.ip_pool[0].clone();
        }
        
        let mut rng = rand::thread_rng();
        let idx = rand::Rng::gen_range(&mut rng, 0..healthy_ips.len());
        healthy_ips[idx].clone()
    }

    fn select_round_robin(&self) -> Arc<IPInfo> {
        for _ in 0..self.ip_pool.len() {
            let mut current = self.current_index.lock().unwrap();
            *current = (*current + 1) % self.ip_pool.len();
            let index = *current;
            drop(current);
            
            if matches!(self.ip_pool[index].health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown) {
                return self.ip_pool[index].clone();
            }
        }
        
        self.ip_pool[0].clone()
    }

    fn select_least_used(&self) -> Arc<IPInfo> {
        self.ip_pool
            .iter()
            .filter(|ip| matches!(ip.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown))
            .min_by_key(|ip| ip.use_count)
            .unwrap_or(&self.ip_pool[0])
            .clone()
    }

    fn select_performance_based(&self) -> Arc<IPInfo> {
        let healthy_ips: Vec<_> = self.ip_pool
            .iter()
            .filter(|ip| matches!(ip.health_status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unknown))
            .collect();
        
        if healthy_ips.is_empty() {
            return self.ip_pool[0].clone();
        }
        
        match healthy_ips.iter().min_by(|a, b| {
            let success_rate_a = a.success_count as f64 / (a.success_count + a.failure_count + 1) as f64;
            let success_rate_b = b.success_count as f64 / (b.success_count + b.failure_count + 1) as f64;
            let latency_cmp = a.latency.cmp(&b.latency);
            
            let rate_cmp = success_rate_b.partial_cmp(&success_rate_a).unwrap_or(std::cmp::Ordering::Equal);
            
            match rate_cmp {
                std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
                std::cmp::Ordering::Less => std::cmp::Ordering::Less,
                std::cmp::Ordering::Equal => latency_cmp,
            }
        }) {
            Some(best) => (*best).clone(),
            None => self.ip_pool[0].clone(),
        }
    }
}
