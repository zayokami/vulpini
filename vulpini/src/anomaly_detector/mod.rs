use std::collections::VecDeque;
use std::time::{Duration, Instant};
use crate::config::AnomalyDetectionConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// How long an anomaly type stays "on cooldown" after firing (30 seconds).
const ALERT_COOLDOWN: Duration = Duration::from_secs(30);

/// How long history samples are retained (5 minutes).
const HISTORY_WINDOW: Duration = Duration::from_secs(300);

/// Maximum number of events kept in the history ring buffer.
const MAX_EVENT_HISTORY: usize = 200;

pub struct AnomalyDetector {
    config: AnomalyDetectionConfig,
    request_rates: VecDeque<(Instant, f64)>,
    latency_history: VecDeque<(Instant, Duration)>,
    error_rates: VecDeque<(Instant, f64)>,
    event_history: VecDeque<AnomalyEvent>,
    /// Per-type cooldown: last time an alert was emitted.
    last_alert: std::collections::HashMap<AnomalyType, Instant>,
}

impl AnomalyDetector {
    pub fn new(config: AnomalyDetectionConfig) -> Self {
        Self {
            config,
            request_rates: VecDeque::with_capacity(1000),
            latency_history: VecDeque::with_capacity(1000),
            error_rates: VecDeque::with_capacity(1000),
            event_history: VecDeque::with_capacity(MAX_EVENT_HISTORY),
            last_alert: std::collections::HashMap::new(),
        }
    }

    pub fn detect(
        &mut self,
        requests_per_second: f64,
        avg_latency: Duration,
        error_rate: f64,
        active_connections: u32,
    ) -> Vec<AnomalyEvent> {
        // Respect the `enabled` flag.
        if !self.config.enabled {
            return Vec::new();
        }

        let now = Instant::now();

        // Run detection BEFORE pushing new data, so the current values
        // are compared against a purely historical baseline.
        self.cleanup(now);

        let mut events = Vec::new();

        if let Some(event) = self.detect_spike(now, requests_per_second) {
            events.push(event);
        }
        if let Some(event) = self.detect_latency(now, avg_latency) {
            events.push(event);
        }
        if let Some(event) = self.detect_error_rate(now, error_rate) {
            events.push(event);
        }
        if let Some(event) = self.detect_connection_flood(now, active_connections) {
            events.push(event);
        }

        // Push AFTER detection so the spike doesn't dilute its own baseline.
        self.request_rates.push_back((now, requests_per_second));
        self.latency_history.push_back((now, avg_latency));
        self.error_rates.push_back((now, error_rate));

        for event in &events {
            self.event_history.push_back(event.clone());
            self.last_alert.insert(event.anomaly_type.clone(), now);
        }

        while self.event_history.len() > MAX_EVENT_HISTORY {
            self.event_history.pop_front();
        }

        events
    }

    pub fn get_event_history(&self) -> Vec<AnomalyEvent> {
        self.event_history.iter().cloned().collect()
    }

    /// Returns true if this anomaly type is still on cooldown.
    fn on_cooldown(&self, now: Instant, anomaly_type: &AnomalyType) -> bool {
        self.last_alert.get(anomaly_type)
            .map_or(false, |last| now.duration_since(*last) < ALERT_COOLDOWN)
    }

    fn cleanup(&mut self, now: Instant) {
        let Some(cutoff) = now.checked_sub(HISTORY_WINDOW) else {
            return; // system uptime < HISTORY_WINDOW, nothing to clean
        };

        while self.request_rates.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.request_rates.pop_front();
        }
        while self.latency_history.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.latency_history.pop_front();
        }
        while self.error_rates.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.error_rates.pop_front();
        }
    }

    fn detect_spike(&self, now: Instant, current_rate: f64) -> Option<AnomalyEvent> {
        if self.on_cooldown(now, &AnomalyType::TrafficSpike) {
            return None;
        }
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
                timestamp: now,
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

    fn detect_latency(&self, now: Instant, current_latency: Duration) -> Option<AnomalyEvent> {
        if self.on_cooldown(now, &AnomalyType::LatencySpike) {
            return None;
        }

        let threshold = Duration::from_millis(self.config.latency_threshold_ms);

        if current_latency > threshold {
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
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

    fn detect_error_rate(&self, now: Instant, current_error_rate: f64) -> Option<AnomalyEvent> {
        if self.on_cooldown(now, &AnomalyType::ErrorRateHigh) {
            return None;
        }

        if current_error_rate > self.config.error_rate_threshold {
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
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

    fn detect_connection_flood(&self, now: Instant, connections: u32) -> Option<AnomalyEvent> {
        if self.on_cooldown(now, &AnomalyType::ConnectionFlood) {
            return None;
        }

        if connections > self.config.connection_threshold {
            Some(AnomalyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
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
