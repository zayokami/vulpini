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
    pub avg_session_duration: Duration,
    pub success_rate: f64,
    pub last_activity: Instant,
}

pub struct BehaviorMonitor {
    active_sessions: DashMap<String, Vec<BehaviorRecord>>,
    patterns: DashMap<String, BehaviorPattern>,
    session_timeout: Duration,
    max_actions_per_session: u32,
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
        let should_save = {
            if let Some(actions) = self.active_sessions.get(session_id) {
                if let Some(last_action) = actions.last() {
                    action.timestamp.duration_since(last_action.timestamp) > self.session_timeout
                        || actions.len() > self.max_actions_per_session as usize
                } else {
                    false
                }
            } else {
                false
            }
        };
        
        if should_save {
            if let Some((_, actions)) = self.active_sessions.remove(session_id) {
                self.save_pattern(session_id, &actions);
            }
        }
        
        let mut actions = self.active_sessions
            .entry(session_id.to_string())
            .or_insert_with(Vec::new);
        
        actions.push(action.clone());
    }

    pub fn analyze_pattern(&self, session_id: &str) -> Option<BehaviorPattern> {
        self.patterns.get(session_id).map(|p| p.clone())
    }

    fn save_pattern(&self, session_id: &str, actions: &[BehaviorRecord]) {
        if actions.is_empty() {
            return;
        }
        
        let mut distribution = Vec::new();
        for action_type in [ActionType::Connect, ActionType::Request, ActionType::Login, ActionType::Download, ActionType::Upload] {
            let count = actions.iter().filter(|a| a.action_type == action_type).count() as u32;
            if count > 0 {
                distribution.push((action_type, count));
            }
        }
        
        let total_duration = actions.last().unwrap().timestamp.duration_since(actions[0].timestamp);
        let avg_session_duration = if !actions.is_empty() {
            total_duration / actions.len() as u32
        } else {
            Duration::ZERO
        };
        
        let success_count = actions.iter().filter(|a| a.success).count();
        let success_rate = success_count as f64 / actions.len() as f64;
        
        let pattern = BehaviorPattern {
            session_id: session_id.to_string(),
            start_time: actions[0].timestamp,
            total_actions: actions.len() as u32,
            action_distribution: distribution,
            avg_session_duration,
            success_rate,
            last_activity: actions.last().unwrap().timestamp,
        };
        
        self.patterns.insert(session_id.to_string(), pattern);
    }
}
