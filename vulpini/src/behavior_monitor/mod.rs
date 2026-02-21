use std::time::{Duration, Instant};
use dashmap::DashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    Connect,
    Request,
    Login,
    Download,
    Upload,
}

#[derive(Debug, Clone)]
pub struct BehaviorRecord {
    pub session_id: String,
    pub timestamp: Instant,
    pub action_type: ActionType,
    pub duration: Duration,
    pub target: String,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub session_id: String,
    pub start_time: Instant,
    pub total_actions: u32,
    pub action_distribution: Vec<(ActionType, u32)>,
    pub total_duration: Duration,
    pub success_rate: f64,
    pub last_activity: Instant,
}

/// Summary of all currently tracked sessions.
#[derive(Debug, Clone)]
pub struct MonitorSnapshot {
    pub active_sessions: usize,
    pub total_patterns: usize,
    pub total_actions_tracked: u64,
}

pub struct BehaviorMonitor {
    active_sessions: DashMap<String, Vec<BehaviorRecord>>,
    patterns: DashMap<String, BehaviorPattern>,
    session_timeout: Duration,
    max_actions_per_session: usize,
}

impl BehaviorMonitor {
    pub fn new(session_timeout: Duration) -> Self {
        Self {
            active_sessions: DashMap::new(),
            patterns: DashMap::new(),
            session_timeout,
            max_actions_per_session: 1000,
        }
    }

    pub fn record_action(&self, session_id: &str, action: &BehaviorRecord) {
        // Check if existing session should be finalized first.
        let should_finalize = self.active_sessions.get(session_id).map_or(false, |actions| {
            actions.len() >= self.max_actions_per_session
                || actions.last().map_or(false, |last| {
                    action.timestamp.duration_since(last.timestamp) > self.session_timeout
                })
        });

        if should_finalize {
            if let Some((_, actions)) = self.active_sessions.remove(session_id) {
                self.save_pattern(session_id, &actions);
            }
        }

        self.active_sessions
            .entry(session_id.to_string())
            .or_default()
            .push(action.clone());
    }

    pub fn analyze_pattern(&self, session_id: &str) -> Option<BehaviorPattern> {
        self.patterns.get(session_id).map(|p| p.clone())
    }

    /// Remove stale sessions that have been idle longer than `session_timeout`.
    /// Should be called periodically from a background task.
    pub fn cleanup_stale_sessions(&self) {
        let now = Instant::now();

        let stale_keys: Vec<String> = self.active_sessions
            .iter()
            .filter(|entry| {
                entry.value().last().map_or(true, |last| {
                    now.duration_since(last.timestamp) > self.session_timeout
                })
            })
            .map(|entry| entry.key().clone())
            .collect();

        for key in stale_keys {
            if let Some((_, actions)) = self.active_sessions.remove(&key) {
                self.save_pattern(&key, &actions);
            }
        }

        // Cap pattern history to prevent unbounded growth.
        const MAX_PATTERNS: usize = 10_000;
        if self.patterns.len() > MAX_PATTERNS {
            // Remove oldest patterns (those with earliest last_activity).
            let mut entries: Vec<(String, Instant)> = self.patterns
                .iter()
                .map(|e| (e.key().clone(), e.value().last_activity))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let remove_count = self.patterns.len() - MAX_PATTERNS;
            for (key, _) in entries.into_iter().take(remove_count) {
                self.patterns.remove(&key);
            }
        }
    }

    pub fn snapshot(&self) -> MonitorSnapshot {
        let total_actions: u64 = self.active_sessions
            .iter()
            .map(|e| e.value().len() as u64)
            .sum();
        MonitorSnapshot {
            active_sessions: self.active_sessions.len(),
            total_patterns: self.patterns.len(),
            total_actions_tracked: total_actions,
        }
    }

    fn save_pattern(&self, session_id: &str, actions: &[BehaviorRecord]) {
        if actions.is_empty() {
            return;
        }

        let first = &actions[0];
        let last = &actions[actions.len() - 1];

        // Build distribution from actual data.
        let mut dist_map = std::collections::HashMap::<ActionType, u32>::new();
        for a in actions {
            *dist_map.entry(a.action_type).or_insert(0) += 1;
        }
        let action_distribution: Vec<(ActionType, u32)> = dist_map.into_iter().collect();

        let total_duration = last.timestamp.duration_since(first.timestamp);
        let success_count = actions.iter().filter(|a| a.success).count();
        let success_rate = success_count as f64 / actions.len() as f64;

        let pattern = BehaviorPattern {
            session_id: session_id.to_string(),
            start_time: first.timestamp,
            total_actions: actions.len() as u32,
            action_distribution,
            total_duration,
            success_rate,
            last_activity: last.timestamp,
        };

        self.patterns.insert(session_id.to_string(), pattern);
    }
}
