use std::sync::Arc;
use parking_lot::Mutex;
use std::time::Duration;
use crate::config::RoutingConfig;

#[derive(Debug, Clone)]
pub struct RouteTarget {
    pub ip: String,
    pub port: u16,
    pub latency: Duration,
    pub reliability: f64,
    pub load: f64,
}

#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub selected_target: Option<RouteTarget>,
    pub route_type: RouteType,
    pub estimated_latency: Duration,
    pub fallback_targets: Vec<RouteTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RouteType {
    Direct,
    Proxy,
}

pub struct SmartRouter {
    config: RoutingConfig,
    targets: Vec<Arc<RouteTarget>>,
    target_stats: Vec<Mutex<TargetStats>>,
    current_index: Mutex<usize>,
}

#[derive(Debug, Default)]
struct TargetStats {
    total_requests: u64,
    successful_requests: u64,
    total_latency: Duration,
    current_connections: u32,
}

impl SmartRouter {
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config,
            targets: Vec::new(),
            target_stats: Vec::new(),
            current_index: Mutex::new(0),
        }
    }

    pub fn add_target(&mut self, ip: &str, port: u16) {
        let target = Arc::new(RouteTarget {
            ip: ip.to_string(),
            port,
            latency: Duration::from_millis(100),
            reliability: 0.95,
            load: 0.0,
        });
        
        self.targets.push(target);
        self.target_stats.push(Mutex::new(TargetStats::default()));
    }

    pub fn select_route(&mut self) -> RoutingDecision {
        if self.targets.is_empty() {
            return RoutingDecision {
                selected_target: None,
                route_type: RouteType::Direct,
                estimated_latency: Duration::MAX,
                fallback_targets: vec![],
            };
        }
        
        let threshold = Duration::from_millis(self.config.max_latency_threshold_ms);
        
        let available_indices: Vec<usize> = self.targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.latency < threshold && t.reliability >= self.config.min_reliability_threshold)
            .map(|(i, _)| i)
            .collect();
        
        if available_indices.is_empty() {
            let best = self.targets[0].clone();
            return RoutingDecision {
                selected_target: Some(best.as_ref().clone()),
                route_type: RouteType::Proxy,
                estimated_latency: best.latency,
                fallback_targets: vec![],
            };
        }
        
        let selected_index = match self.config.load_balancing.as_str() {
            "roundrobin" => self.round_robin_select(&available_indices),
            "leastconnections" => self.least_connections_select(&available_indices),
            "fastest" => self.fastest_response_select(&available_indices),
            _ => self.fastest_response_select(&available_indices),
        };
        
        let selected_target = self.targets[selected_index].clone();
        
        let fallback_targets: Vec<RouteTarget> = available_indices
            .iter()
            .filter(|&&i| i != selected_index)
            .map(|&i| self.targets[i].as_ref().clone())
            .collect();
        
        RoutingDecision {
            selected_target: Some(selected_target.as_ref().clone()),
            route_type: RouteType::Proxy,
            estimated_latency: selected_target.latency,
            fallback_targets,
        }
    }

    pub fn record_result(&mut self, ip: &str, success: bool, latency: Duration) {
        if let Some(index) = self.targets.iter().position(|t| t.ip == ip) {
            let mut stats = self.target_stats[index].lock();
            stats.total_requests += 1;
            stats.total_latency += latency;

            if success {
                stats.successful_requests += 1;
            }
        }
    }

    fn round_robin_select(&self, available_indices: &[usize]) -> usize {
        let mut current = self.current_index.lock();
        *current = (*current + 1) % self.targets.len();
        let index = *current;
        drop(current);
        
        if available_indices.contains(&index) {
            index
        } else {
            available_indices[0]
        }
    }

    fn least_connections_select(&self, available_indices: &[usize]) -> usize {
        available_indices
            .iter()
            .min_by_key(|&&i| {
                self.target_stats
                    .get(i)
                    .map(|s| s.lock().current_connections)
                    .unwrap_or(0)
            })
            .copied()
            .unwrap_or(available_indices[0])
    }

    fn fastest_response_select(&self, available_indices: &[usize]) -> usize {
        available_indices
            .iter()
            .min_by(|&&i, &&j| self.targets[i].latency.cmp(&self.targets[j].latency))
            .copied()
            .unwrap_or(available_indices[0])
    }
}
