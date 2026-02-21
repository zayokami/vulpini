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

/// Internal per-target statistics, protected by its own Mutex so
/// `record_result(&self)` can update without `&mut self`.
#[derive(Debug)]
struct TargetStats {
    total_requests: u64,
    successful_requests: u64,
    avg_latency: Duration,
    current_connections: u32,
}

impl Default for TargetStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            avg_latency: Duration::from_millis(100),
            current_connections: 0,
        }
    }
}

struct TargetEntry {
    ip: String,
    port: u16,
    stats: Mutex<TargetStats>,
}

pub struct SmartRouter {
    config: RoutingConfig,
    targets: Vec<TargetEntry>,
    current_index: Mutex<usize>,
}

impl SmartRouter {
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            config,
            targets: Vec::new(),
            current_index: Mutex::new(0),
        }
    }

    pub fn add_target(&mut self, ip: &str, port: u16) {
        if self.targets.iter().any(|t| t.ip == ip) {
            return;
        }
        self.targets.push(TargetEntry {
            ip: ip.to_string(),
            port,
            stats: Mutex::new(TargetStats::default()),
        });
    }

    /// Build a `RouteTarget` snapshot from live stats.
    fn snapshot(entry: &TargetEntry) -> RouteTarget {
        let stats = entry.stats.lock();
        let reliability = if stats.total_requests > 0 {
            stats.successful_requests as f64 / stats.total_requests as f64
        } else {
            1.0 // assume healthy until proven otherwise
        };
        RouteTarget {
            ip: entry.ip.clone(),
            port: entry.port,
            latency: stats.avg_latency,
            reliability,
            load: stats.current_connections as f64,
        }
    }

    /// Select the best route based on the configured load-balancing strategy.
    /// Takes `&self` — internal mutability handled by per-field Mutexes.
    pub fn select_route(&self) -> RoutingDecision {
        if self.targets.is_empty() {
            return RoutingDecision {
                selected_target: None,
                route_type: RouteType::Direct,
                estimated_latency: Duration::MAX,
                fallback_targets: vec![],
            };
        }

        let threshold = Duration::from_millis(self.config.max_latency_threshold_ms);
        let min_rel = self.config.min_reliability_threshold;

        // Build snapshots of all targets from live stats.
        let snapshots: Vec<(usize, RouteTarget)> = self.targets.iter()
            .enumerate()
            .map(|(i, entry)| (i, Self::snapshot(entry)))
            .collect();

        let available: Vec<(usize, &RouteTarget)> = snapshots.iter()
            .filter(|(_, t)| t.latency < threshold && t.reliability >= min_rel)
            .map(|(i, t)| (*i, t))
            .collect();

        if available.is_empty() {
            // Fallback: pick the first target regardless of thresholds.
            let best = &snapshots[0].1;
            return RoutingDecision {
                selected_target: Some(best.clone()),
                route_type: RouteType::Proxy,
                estimated_latency: best.latency,
                fallback_targets: vec![],
            };
        }

        let selected_idx = match self.config.load_balancing.as_str() {
            "roundrobin" => self.round_robin_select(&available),
            "leastconnections" => self.least_connections_select(&available),
            _ => self.fastest_response_select(&available),
        };

        let selected = &snapshots[selected_idx].1;
        let fallbacks: Vec<RouteTarget> = available.iter()
            .filter(|(i, _)| *i != selected_idx)
            .map(|(_, t)| (*t).clone())
            .collect();

        RoutingDecision {
            selected_target: Some(selected.clone()),
            route_type: RouteType::Proxy,
            estimated_latency: selected.latency,
            fallback_targets: fallbacks,
        }
    }

    /// Record the result of a connection attempt. Updates running-average
    /// latency and success counters for the given target IP.
    /// Takes `&self` — stats are behind per-entry Mutexes.
    pub fn record_result(&self, ip: &str, success: bool, latency: Duration) {
        let Some(entry) = self.targets.iter().find(|t| t.ip == ip) else {
            return;
        };
        let mut stats = entry.stats.lock();
        stats.total_requests += 1;

        // Running average latency.
        let n = stats.total_requests as f64;
        let old_avg = stats.avg_latency.as_secs_f64();
        let new_lat = latency.as_secs_f64();
        stats.avg_latency = Duration::from_secs_f64((old_avg * (n - 1.0) + new_lat) / n);

        if success {
            stats.successful_requests += 1;
        }
    }

    // ── Selection strategies ────────────────────────────────────────────────

    fn round_robin_select(&self, available: &[(usize, &RouteTarget)]) -> usize {
        let len = self.targets.len();
        let mut current = self.current_index.lock();

        for _ in 0..len {
            *current = (*current + 1) % len;
            let idx = *current;
            if available.iter().any(|(i, _)| *i == idx) {
                return idx;
            }
        }

        available[0].0
    }

    fn least_connections_select(&self, available: &[(usize, &RouteTarget)]) -> usize {
        available.iter()
            .min_by(|(_, a), (_, b)| {
                a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| *i)
            .unwrap_or(available[0].0)
    }

    fn fastest_response_select(&self, available: &[(usize, &RouteTarget)]) -> usize {
        available.iter()
            .min_by(|(_, a), (_, b)| a.latency.cmp(&b.latency))
            .map(|(i, _)| *i)
            .unwrap_or(available[0].0)
    }
}
