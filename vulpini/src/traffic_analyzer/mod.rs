use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct TrafficStats {
    pub total_requests: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_connections: u32,
    pub requests_per_second: f64,
    pub bytes_per_second: f64,
    pub avg_latency: Duration,
    pub p50_latency: Duration,
    pub p95_latency: Duration,
    pub p99_latency: Duration,
    pub error_count: u64,
    pub error_rate: f64,
}

pub struct RequestInfo {
    pub timestamp: Instant,
    pub size: u64,
    pub latency: Duration,
    pub protocol: String,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            active_connections: 0,
            requests_per_second: 0.0,
            bytes_per_second: 0.0,
            avg_latency: Duration::ZERO,
            p50_latency: Duration::ZERO,
            p95_latency: Duration::ZERO,
            p99_latency: Duration::ZERO,
            error_count: 0,
            error_rate: 0.0,
        }
    }
}

pub struct TrafficAnalyzer {
    request_history: VecDeque<RequestInfo>,
    byte_history: VecDeque<(Instant, u64, bool)>,
    window_size: Duration,
    current_stats: TrafficStats,
}

impl TrafficAnalyzer {
    pub fn new(window_size: Duration) -> Self {
        Self {
            request_history: VecDeque::with_capacity(10000),
            byte_history: VecDeque::with_capacity(10000),
            window_size,
            current_stats: TrafficStats::default(),
        }
    }

    pub fn record_request(&mut self, request: RequestInfo) {
        self.request_history.push_back(request);
        self.cleanup_expired();
        self.update_stats();
    }

    pub fn record_bytes(&mut self, bytes_in: u64, bytes_out: u64) {
        let now = Instant::now();
        self.byte_history.push_back((now, bytes_in, true));
        self.byte_history.push_back((now, bytes_out, false));
        self.cleanup_expired();
        self.update_stats();
    }

    pub fn update_connections(&mut self, active: u32) {
        self.current_stats.active_connections = active;
    }

    pub fn get_stats(&self) -> &TrafficStats {
        &self.current_stats
    }

    fn cleanup_expired(&mut self) {
        let cutoff = Instant::now() - self.window_size;
        
        while let Some(oldest) = self.request_history.front() {
            if oldest.timestamp < cutoff {
                self.request_history.pop_front();
            } else {
                break;
            }
        }
        
        while let Some(oldest) = self.byte_history.front() {
            if oldest.0 < cutoff {
                self.byte_history.pop_front();
            } else {
                break;
            }
        }
    }

    fn update_stats(&mut self) {
        let now = Instant::now();
        
        if self.request_history.is_empty() {
            return;
        }
        
        let recent_requests: Vec<_> = self.request_history
            .iter()
            .filter(|r| now.duration_since(r.timestamp) < self.window_size)
            .collect();
        
        if recent_requests.is_empty() {
            return;
        }
        
        let total_requests = recent_requests.len() as u64;
        let total_bytes = recent_requests.iter().map(|r| r.size).sum::<u64>();
        let total_latency: Duration = recent_requests.iter().map(|r| r.latency).sum::<Duration>();
        
        let errors = recent_requests.iter().filter(|r| r.latency > Duration::from_secs(10)).count();
        
        self.current_stats.total_requests = total_requests;
        self.current_stats.total_bytes_in = self.byte_history.iter().filter(|(_, _, is_in)| *is_in).map(|(_, bytes, _)| *bytes).sum::<u64>();
        self.current_stats.total_bytes_out = self.byte_history.iter().filter(|(_, _, is_in)| !*is_in).map(|(_, bytes, _)| *bytes).sum::<u64>();
        self.current_stats.requests_per_second = total_requests as f64 / self.window_size.as_secs() as f64;
        self.current_stats.bytes_per_second = total_bytes as f64 / self.window_size.as_secs() as f64;
        
        let n = total_requests as u32;
        self.current_stats.avg_latency = if n > 0 { total_latency / n } else { Duration::ZERO };
        
        let mut latencies: Vec<Duration> = recent_requests.iter().map(|r| r.latency).collect();
        latencies.sort();
        
        let n_lat = latencies.len();
        if n_lat > 0 {
            self.current_stats.p50_latency = latencies[n_lat * 50 / 100];
            self.current_stats.p95_latency = if n_lat >= 20 { latencies[n_lat * 95 / 100] } else { latencies[n_lat - 1] };
            self.current_stats.p99_latency = if n_lat >= 100 { latencies[n_lat * 99 / 100] } else { latencies[n_lat - 1] };
        }
        
        self.current_stats.error_count = errors as u64;
        self.current_stats.error_rate = errors as f64 / n as f64;
    }
}
