use std::collections::VecDeque;
use std::time::{Duration, Instant};
use crate::config::AnomalyDetectionConfig;

#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyType {
    TrafficSpike,
    LatencySpike,
    ErrorRateHigh,
    ConnectionFlood,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    pub id: String,
    pub timestamp: Instant,
    pub anomaly_type: AnomalyType,
    pub value: f64,
    pub threshold: f64,
    pub description: String,
    pub severity: Severity,
}

pub struct AnomalyDetector {
    config: AnomalyDetectionConfig,
    request_rates: VecDeque<(Instant, f64)>,
    latency_history: VecDeque<(Instant, Duration)>,
    error_rates: VecDeque<(Instant, f64)>,
    event_history: VecDeque<AnomalyEvent>,
}

impl AnomalyDetector {
    pub fn new(config: AnomalyDetectionConfig) -> Self {
        Self {
            config,
            request_rates: VecDeque::with_capacity(1000),
            latency_history: VecDeque::with_capacity(1000),
            error_rates: VecDeque::with_capacity(1000),
            event_history: VecDeque::with_capacity(100),
        }
    }

    pub fn detect(
        &mut self,
        requests_per_second: f64,
        avg_latency: Duration,
        error_rate: f64,
        active_connections: u32,
    ) -> Vec<AnomalyEvent> {
        let mut events = Vec::new();
        let now = Instant::now();
        
        self.request_rates.push_back((now, requests_per_second));
        self.latency_history.push_back((now, avg_latency));
        self.error_rates.push_back((now, error_rate));
        
        self.cleanup(now);
        
        if let Some(event) = self.detect_spike(requests_per_second) {
            events.push(event);
        }
        
        if let Some(event) = self.detect_latency(avg_latency) {
            events.push(event);
        }
        
        if let Some(event) = self.detect_error_rate(error_rate) {
            events.push(event);
        }
        
        if let Some(event) = self.detect_connection_flood(active_connections) {
            events.push(event);
        }
        
        for event in &events {
            self.event_history.push_back(event.clone());
        }
        
        while self.event_history.len() > 100 {
            self.event_history.pop_front();
        }
        
        events
    }

    pub fn get_event_history(&self) -> Vec<AnomalyEvent> {
        self.event_history.iter().cloned().collect()
    }

    fn cleanup(&mut self, now: Instant) {
        let cutoff = now - Duration::from_secs(300);
        
        while let Some((ts, _)) = self.request_rates.front() {
            if *ts < cutoff {
                self.request_rates.pop_front();
            } else {
                break;
            }
        }
        
        while let Some((ts, _)) = self.latency_history.front() {
            if *ts < cutoff {
                self.latency_history.pop_front();
            } else {
                break;
            }
        }
        
        while let Some((ts, _)) = self.error_rates.front() {
            if *ts < cutoff {
                self.error_rates.pop_front();
            } else {
                break;
            }
        }
    }

    fn detect_spike(&self, current_rate: f64) -> Option<AnomalyEvent> {
        if self.request_rates.len() < 5 {
            return None;
        }
        
        let sum: f64 = self.request_rates.iter().map(|(_, rate)| *rate).sum();
        let avg = sum / self.request_rates.len() as f64;
        
        if current_rate > avg * self.config.spike_threshold {
            let severity = if current_rate > avg * self.config.spike_threshold * 2.0 {
                Severity::High
            } else {
                Severity::Medium
            };
            
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Instant::now(),
                anomaly_type: AnomalyType::TrafficSpike,
                value: current_rate,
                threshold: avg * self.config.spike_threshold,
                description: format!(
                    "Traffic spike detected: current {:.2} req/s, average {:.2} req/s",
                    current_rate, avg
                ),
                severity,
            })
        } else {
            None
        }
    }

    fn detect_latency(&self, current_latency: Duration) -> Option<AnomalyEvent> {
        let threshold = Duration::from_millis(self.config.latency_threshold_ms);
        
        if current_latency > threshold {
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Instant::now(),
                anomaly_type: AnomalyType::LatencySpike,
                value: current_latency.as_secs_f64(),
                threshold: threshold.as_secs_f64(),
                description: format!(
                    "High latency detected: {:.2}ms, threshold {:.2}ms",
                    current_latency.as_secs_f64() * 1000.0,
                    threshold.as_secs_f64() * 1000.0
                ),
                severity: Severity::Medium,
            })
        } else {
            None
        }
    }

    fn detect_error_rate(&self, current_error_rate: f64) -> Option<AnomalyEvent> {
        if current_error_rate > self.config.error_rate_threshold {
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Instant::now(),
                anomaly_type: AnomalyType::ErrorRateHigh,
                value: current_error_rate,
                threshold: self.config.error_rate_threshold,
                description: format!(
                    "High error rate: {:.2}%, threshold {:.2}%",
                    current_error_rate * 100.0,
                    self.config.error_rate_threshold * 100.0
                ),
                severity: Severity::High,
            })
        } else {
            None
        }
    }

    fn detect_connection_flood(&self, connections: u32) -> Option<AnomalyEvent> {
        if connections > self.config.connection_threshold {
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Instant::now(),
                anomaly_type: AnomalyType::ConnectionFlood,
                value: connections as f64,
                threshold: self.config.connection_threshold as f64,
                description: format!(
                    "Connection flood: {} active connections, threshold {}",
                    connections, self.config.connection_threshold
                ),
                severity: Severity::High,
            })
        } else {
            None
        }
    }
}
